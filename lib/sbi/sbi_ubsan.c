#include <sbi/sbi_string.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_ubsan.h>

#define REPORTED_BIT 31

#if (BITS_PER_LONG == 64) && defined(__BIG_ENDIAN)
#define COLUMN_MASK (~(1U << REPORTED_BIT))
#define LINE_MASK   (~0U)
#else
#define COLUMN_MASK   (~0U)
#define LINE_MASK (~(1U << REPORTED_BIT))
#endif

#define VALUE_LENGTH 40
#define IS_ALIGNED(x, a)        (((x) & ((typeof(x))(a) - 1)) == 0)
#define BIT(nr) (1UL << (nr))
#define __attribute_const__             __attribute__((__const__))

#define ffs(x) __builtin_ffs(x)

typedef long ssize_t;

static const char * const type_check_kinds[] = {
	"load of",
	"store to",
	"reference binding to",
	"member access within",
	"member call on",
	"constructor call on",
	"downcast of",
	"downcast of"
};


static bool type_is_signed(struct type_descriptor *type)
{
	return  type->type_info & 1;
}

static unsigned type_bit_width(struct type_descriptor *type)
{
	return 1 << (type->type_info >> 1);
}

static bool is_inline_int(struct type_descriptor *type)
{
	unsigned inline_bits = sizeof(unsigned long)*8;
	unsigned bits = type_bit_width(type);

	return bits <= inline_bits;
}

static s_max get_signed_val(struct type_descriptor *type, void *val)
{
	if (is_inline_int(type)) {
		unsigned extra_bits = sizeof(s_max)*8 - type_bit_width(type);
		unsigned long ulong_val = (unsigned long)val;

		return ((s_max)ulong_val) << extra_bits >> extra_bits;
	}

	if (type_bit_width(type) == 64)
		return *(s64 *)val;

	return *(s_max *)val;
}

static bool val_is_negative(struct type_descriptor *type, void *val)
{
	return type_is_signed(type) && get_signed_val(type, val) < 0;
}

static u_max get_unsigned_val(struct type_descriptor *type, void *val)
{
	if (is_inline_int(type))
		return (unsigned long)val;

	if (type_bit_width(type) == 64)
		return *(u64 *)val;

	return *(u_max *)val;
}


static void ubsan_prologue(struct source_location *loc, const char *reason)
{

	sbi_printf("================================================================================\n");//pr_warn(CUT_HERE);

	sbi_printf("UBSAN: %s in %s:%d:%d\n", reason, loc->file_name,
		loc->line & LINE_MASK, loc->column & COLUMN_MASK); 
}

static void ubsan_epilogue(void)
{
	sbi_printf("----------------------\n");
}

static void handle_overflow(struct overflow_data *data, void *lhs,
			void *rhs, char op)
{

	struct type_descriptor *type = data->type;

	ubsan_prologue(&data->location, type_is_signed(type) ?
			"signed-integer-overflow" :
			"unsigned-integer-overflow");
	
    sbi_printf("%c operation cannot be represented in type %s with those operands\n",
		op,
		type->type_name);
    

	ubsan_epilogue();
}


void __ubsan_handle_add_overflow(void *data,
				void *lhs, void *rhs)
{

	handle_overflow(data, lhs, rhs, '+');
}


void __ubsan_handle_sub_overflow(void *data,
				void *lhs, void *rhs)
{
	handle_overflow(data, lhs, rhs, '-');
}

void __ubsan_handle_mul_overflow(void *data,
				void *lhs, void *rhs)
{
	handle_overflow(data, lhs, rhs, '*');
}

void __ubsan_handle_negate_overflow(void *_data, void *old_val)
{
	struct overflow_data *data = _data;

	ubsan_prologue(&data->location, "negation-overflow");

    sbi_printf("negation of this value cannot be represented in type %s\n",
    data->type->type_name);

	ubsan_epilogue();
}

void __ubsan_handle_implicit_conversion(void *_data, void *from_val, void *to_val)
{
	struct implicit_conversion_data *data = _data;
	char from_val_str[VALUE_LENGTH];

	ubsan_prologue(&data->location, "implicit-conversion");
    	
    sbi_printf("cannot represent %s value %s during %s %s: truncated.\n",
        data->from_type->type_name,
        from_val_str,
        type_check_kinds[data->type_check_kind],
        data->to_type->type_name);
    

	ubsan_epilogue();
}


void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
{
	struct overflow_data *data = _data;

	ubsan_prologue(&data->location, "division-overflow");

	if (type_is_signed(data->type) && get_signed_val(data->type, rhs) == -1)
		sbi_printf("division of this value by -1 cannot be represented in type %s\n",
			 data->type->type_name);
	else
		sbi_printf("division by zero\n");

     

	ubsan_epilogue();
}

static void handle_null_ptr_deref(struct type_mismatch_data_common *data)
{

	ubsan_prologue(data->location, "null-ptr-deref");

	sbi_printf("%s null pointer of type %s\n",
		type_check_kinds[data->type_check_kind],
		data->type->type_name);

	ubsan_epilogue();
}

static void handle_misaligned_access(struct type_mismatch_data_common *data,
				unsigned long ptr)
{

	ubsan_prologue(data->location, "misaligned-access");

	sbi_printf("%s misaligned address %p for type %s\n",
		type_check_kinds[data->type_check_kind],
		(void *)ptr, data->type->type_name);
	sbi_printf("which requires %ld byte alignment\n", data->alignment);

	ubsan_epilogue();
}

static void handle_object_size_mismatch(struct type_mismatch_data_common *data,
					unsigned long ptr)
{

	ubsan_prologue(data->location, "object-size-mismatch");
	sbi_printf("%s address %p with insufficient space\n",
		type_check_kinds[data->type_check_kind],
		(void *) ptr);
	sbi_printf("for an object of type %s\n", data->type->type_name);
	ubsan_epilogue();
}

static void ubsan_type_mismatch_common(struct type_mismatch_data_common *data,
				unsigned long ptr)
{

	if (!ptr)
		handle_null_ptr_deref(data);
	else if (data->alignment && !IS_ALIGNED(ptr, data->alignment))
		handle_misaligned_access(data, ptr);
	else
		handle_object_size_mismatch(data, ptr);

}

void __ubsan_handle_type_mismatch(struct type_mismatch_data *data,
				void *ptr)
{
	struct type_mismatch_data_common common_data = {
		.location = &data->location,
		.type = data->type,
		.alignment = data->alignment,
		.type_check_kind = data->type_check_kind
	};

	ubsan_type_mismatch_common(&common_data, (unsigned long)ptr);
}

void __ubsan_handle_type_mismatch_v1(void *_data, void *ptr)
{
	struct type_mismatch_data_v1 *data = _data;
	struct type_mismatch_data_common common_data = {
		.location = &data->location,
		.type = data->type,
		.alignment = 1UL << data->log_alignment,
		.type_check_kind = data->type_check_kind
	};

	ubsan_type_mismatch_common(&common_data, (unsigned long)ptr);
}

void __ubsan_handle_out_of_bounds(void *_data, void *index)
{
	struct out_of_bounds_data *data = _data;

	ubsan_prologue(&data->location, "array-index-out-of-bounds");

    sbi_printf("used index is out of range for type %s\n",
		data->array_type->type_name);
	ubsan_epilogue();


}

void __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs)
{
	struct shift_out_of_bounds_data *data = _data;
	struct type_descriptor *rhs_type = data->rhs_type;
	struct type_descriptor *lhs_type = data->lhs_type;

	ubsan_prologue(&data->location, "shift-out-of-bounds");

    if (val_is_negative(rhs_type, rhs))
    sbi_printf("shift exponent is negative\n");

	else if (get_unsigned_val(rhs_type, rhs) >=
		type_bit_width(lhs_type))
		sbi_printf("shift exponent is too large for %u-bit type %s\n",
			type_bit_width(lhs_type),
			lhs_type->type_name);
	else if (val_is_negative(lhs_type, lhs))
		sbi_printf("left shift of negative value\n");
	else
		sbi_printf("left shift of this value by this places cannot be"
			" represented in type %s\n", lhs_type->type_name);

	ubsan_epilogue();

}

void __ubsan_handle_builtin_unreachable(void *_data)
{
	struct unreachable_data *data = _data;
	ubsan_prologue(&data->location, "unreachable");
	sbi_printf("calling __builtin_unreachable()\n");
	ubsan_epilogue();
}

void __ubsan_handle_load_invalid_value(void *_data, void *val)
{
	struct invalid_value_data *data = _data;

	ubsan_prologue(&data->location, "invalid-load");

   	sbi_printf("load of this value is not a valid value for type %s\n", data->type->type_name);

	ubsan_epilogue();

}

void __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
					 unsigned long align,
					 unsigned long offset)
{
	struct alignment_assumption_data *data = _data;
	unsigned long real_ptr;

	ubsan_prologue(&data->location, "alignment-assumption");

	if (offset)
		sbi_printf("assumption of %lu byte alignment (with offset of %lu byte) for pointer of type %s failed",
		       align, offset, data->type->type_name);
	else
		sbi_printf("assumption of %lu byte alignment for pointer of type %s failed",
		       align, data->type->type_name);

	real_ptr = ptr - offset;
	sbi_printf("%saddress is %lu aligned, misalignment offset is %lu bytes",
	       offset ? "offset " : "", BIT(real_ptr ? ffs(real_ptr) : 0),
	       real_ptr & (align - 1));

	ubsan_epilogue();
}
