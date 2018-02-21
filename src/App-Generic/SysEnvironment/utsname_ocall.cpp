#include <sys/utsname.h>

#include "GenericExecutionEnclave_u.h"

int ocall_uname(struct utsname *name)
{
	return uname(name);
}