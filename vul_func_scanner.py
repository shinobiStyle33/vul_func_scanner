#This script scan vulnerable c functions
#@author shinobiStyle
#@category scanner

# Reference https://www.jpcert.or.jp/sc-rules/c-msc24-c.html

def list_xref_call_functions(func_names):
    manager = currentProgram.getFunctionManager()
    for func in manager.getFunctions(True):
        if func.getName() in func_names:
            for xref in getReferencesTo(func.getEntryPoint()):
                if xref.getReferenceType().toString() == 'UNCONDITIONAL_CALL':
                    print('{} is called at {}'.format(func.getName(), xref.getFromAddress()))


dangerous_func_name = [	'gets', 'asctime', 'atof', 'atoi', 'atol', 'atoll', 'ctime', 'fopen', 'freopen', 'rewind', 'setbuf', \
			'bsearch', 'fprintf', 'fscanf', 'fwprintf', 'fwscanf', 'getenv', 'gmtime', 'localtime', 'mbsrtowcs',\
 			'mbstowcs', 'memcpy', 'memmove', 'printf', 'qsort', 'setbuf', 'snprintf', 'sprintf', 'sscanf', 'strcat',\
			'strcpy', 'strerror', 'strncat', 'strncpy', 'strtok', 'swprintf', 'swscanf', 'vfprintf', 'vfscanf',\
			'vfwprintf', 'vfwscanf', 'vprintf', 'vscanf', 'vsnprintf', 'vsprintf', 'vsscanf', 'vswprintf', 'vswscanf',\
			'vwprintf', 'vwscanf', 'wcrtomb', 'wcscat', 'wcscpy', 'wcsncat', 'wcsncpy', 'wcsrtombs', 'wcstok', 'wcstombs',\
			'wctomb', 'wmemcpy', 'wmemmove', 'wprintf', 'wscanf']

list_xref_call_functions(dangerous_func_name)

