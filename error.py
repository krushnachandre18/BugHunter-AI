from flask import Flask, request, jsonify, send_file
import ast
import re

app = Flask(__name__)


@app.route("/")
def home():
    return send_file("error.html")


@app.route("/error.css")
def css():
    return send_file("error.css")


@app.route("/error.js")
def js():
    return send_file("error.js")


# =========================================================
# COMMON RESPONSE
# =========================================================

def error_result(language, error, reason, fix, line=None, severity="Error"):
    return {
        "status": "error",
        "language": language,
        "severity": severity,
        "line": line,
        "error": error,
        "reason": reason,
        "fix": fix
    }


def success_result(language):
    return {
        "status": "success",
        "language": language,
        "severity": "Info",
        "line": None,
        "error": "No Known Error Found",
        "reason": "No known error pattern was detected.",
        "fix": "Try another test case or use AI analysis."
    }


def check_patterns(code, language, patterns):

    for pattern, error, reason, fix, *extra in patterns:

        severity = extra[0] if extra else "Error"

        try:
            match = re.search(
                pattern,
                code,
                re.IGNORECASE | re.MULTILINE
            )
        except re.error:
            continue

        if match:

            line = code[:match.start()].count("\n") + 1

            return error_result(
                language,
                error,
                reason,
                fix,
                line,
                severity
            )

    return None


# =========================================================
# PYTHON - 50+ RULES
# =========================================================

PYTHON_PATTERNS = [

    (
        r"\bprint\s+['\"]",
        "Python 2 Print Syntax",
        "Old Python print syntax detected.",
        "Use print(...) instead."
    ),

    (
        r"\bprintff\s*\(",
        "Typo Error",
        "printff is not a Python function.",
        "Use print()."
    ),

    (
        r"\bdef\s+\w+\s*\([^)]*\)\s*(?!:)",
        "Missing Colon",
        "Function definition requires ':'.",
        "Add ':' after the function definition."
    ),

    (
        r"(?m)^\s*(if|elif|else|for|while|try|except|finally|class|with)\b[^:\n]*$",
        "Missing Colon",
        "Python block appears to be missing ':'.",
        "Add ':' at the end."
    ),

    (
        r"\bTrue\s*=",
        "Invalid Assignment",
        "True is a Python constant.",
        "Do not assign a value to True."
    ),

    (
        r"\bFalse\s*=",
        "Invalid Assignment",
        "False is a Python constant.",
        "Do not assign a value to False."
    ),

    (
        r"\bNone\s*=",
        "Invalid Assignment",
        "None is a Python constant.",
        "Do not assign a value to None."
    ),

    (
        r"\bfor\s+\w+\s+in\s*$",
        "Incomplete For Loop",
        "The for loop has no iterable.",
        "Provide an iterable after 'in'."
    ),

    (
        r"\bwhile\s*:\s*$",
        "Incomplete While Loop",
        "while requires a condition.",
        "Add a Boolean condition."
    ),

    (
        r"\bif\s*:\s*$",
        "Incomplete If Statement",
        "if requires a condition.",
        "Add a condition."
    ),

    (
        r"\belse\s+\w",
        "Invalid Else Syntax",
        "else cannot have a normal condition.",
        "Use elif for another condition."
    ),

    (
        r"\bimport\s*$",
        "Incomplete Import",
        "No module was specified.",
        "Specify a module."
    ),

    (
        r"\bfrom\s+\w+\s+import\s*$",
        "Incomplete Import",
        "import statement is incomplete.",
        "Specify the object to import."
    ),

    (
        r"\bopen\s*\([^)]*$",
        "Unclosed Function Call",
        "open() is not closed.",
        "Add ')'."
    ),

    (
        r"\bprint\s*\([^)]*$",
        "Unclosed Print Call",
        "print() is not closed.",
        "Add ')'."
    ),

    (
        r"\binput\s*\([^)]*$",
        "Unclosed Input Call",
        "input() is not closed.",
        "Add ')'."
    ),

    (
        r"\blen\s*\([^)]*$",
        "Unclosed len Call",
        "len() is not closed.",
        "Add ')'."
    ),

    (
        r"\brange\s*\([^)]*$",
        "Unclosed range Call",
        "range() is not closed.",
        "Add ')'."
    ),

    (
        r"\bint\s*\([^)]*$",
        "Unclosed int Call",
        "int() is not closed.",
        "Add ')'."
    ),

    (
        r"\bstr\s*\([^)]*$",
        "Unclosed str Call",
        "str() is not closed.",
        "Add ')'."
    ),

    (
        r"\b\d+\s*/\s*0\b",
        "Division by Zero",
        "The code divides by zero.",
        "Check the denominator."
    ),

    (
        r"\b0\s*/\s*0\b",
        "Division by Zero",
        "The code divides zero by zero.",
        "Use a non-zero denominator."
    ),

    (
        r"\[[^\]]*\]\s*\[\s*['\"]",
        "Invalid List Index",
        "A string key is being used on a list.",
        "Use an integer index."
    ),

    (
        r"\.append\s*\([^)]*\)\s*\[",
        "Append Result Misuse",
        "append() returns None.",
        "Append first, then access the list."
    ),

    (
        r"\.sort\s*\([^)]*\)\s*\[",
        "Sort Result Misuse",
        "sort() modifies the list and returns None.",
        "Sort first, then access the list."
    ),

    (
        r"\.reverse\s*\([^)]*\)\s*\[",
        "Reverse Result Misuse",
        "reverse() modifies the list and returns None.",
        "Reverse first, then access the list."
    ),

    (
        r"\beval\s*\(",
        "Dangerous eval Usage",
        "eval() executes dynamically supplied Python code.",
        "Avoid eval() for untrusted input.",
        "Warning"
    ),

    (
        r"\bexec\s*\(",
        "Dangerous exec Usage",
        "exec() executes dynamically supplied Python code.",
        "Avoid exec() for untrusted input.",
        "Warning"
    ),

    (
        r"\binput\s*\(.*\)\s*==\s*\d",
        "Input Type Error",
        "input() returns a string in Python 3.",
        "Convert input using int() or float()."
    ),

    (
        r"\b\d+\s*\+\s*['\"]",
        "Type Error",
        "Number and string are being added.",
        "Convert them to compatible types."
    ),

    (
        r"['\"][^'\"]*['\"]\s*-\s*\w+",
        "Type Error",
        "String is being used in subtraction.",
        "Convert the value to a number."
    ),

    (
        r"(?m)^\s*global\s*$",
        "Incomplete Global Statement",
        "global requires a variable name.",
        "Specify the variable."
    ),

    (
        r"(?m)^\s*nonlocal\s*$",
        "Incomplete Nonlocal Statement",
        "nonlocal requires a variable.",
        "Specify the variable."
    ),

    (
        r"(?m)^\s*assert\s*$",
        "Incomplete Assert",
        "assert requires an expression.",
        "Provide a condition."
    ),

    (
        r"(?m)^\s*raise\s*$",
        "Incomplete Raise",
        "raise requires an exception.",
        "Raise a specific exception."
    ),

    (
        r"\basync\s+def\s+\w+\s*\([^)]*\)\s*(?!:)",
        "Async Function Error",
        "async def requires ':'.",
        "Add ':'."
    ),

    (
        r"\bawait\s*$",
        "Invalid Await",
        "await requires an expression.",
        "Await an async operation."
    ),

    (
        r"\bwith\s+open\s*\([^)]*\)\s+as\s*$",
        "Incomplete With Statement",
        "with ... as requires a variable.",
        "Add a variable and ':'."
    ),

    (
        r"\b(lambda)\s+\w+\s*:\s*$",
        "Incomplete Lambda",
        "Lambda has no expression.",
        "Provide an expression."
    ),

    (
        r"\bimport\s+\w+\s+as\s*$",
        "Incomplete Import Alias",
        "Import alias is incomplete.",
        "Provide an alias."
    ),

    (
        r"\b\d+\s*//\s*0\b",
        "Floor Division By Zero",
        "Floor division by zero is invalid.",
        "Use a non-zero denominator."
    ),

    (
        r"\b\d+\s*%\s*0\b",
        "Modulo By Zero",
        "Modulo by zero is invalid.",
        "Use a non-zero divisor."
    ),

    (
        r"\bdel\s+\w+\s*$",
        "Possible Deleted Variable",
        "Variable is deleted and may be used later.",
        "Check variable usage after del.",
        "Warning"
    ),

    (
        r"\bexcept\s*:\s*$",
        "Bare Except",
        "Bare except catches every exception.",
        "Catch a specific exception.",
        "Warning"
    ),

    (
        r"\bfinally\s+except\b",
        "Invalid Exception Structure",
        "finally cannot be followed by except.",
        "Use except before finally."
    ),

    (
        r"\belse\s+elif\b",
        "Invalid Conditional Structure",
        "elif must come before else.",
        "Reorder elif and else."
    ),

    (
        r"\breturn\s+\w+\s+\w+",
        "Possible Invalid Return",
        "Return statement may contain an invalid expression.",
        "Check the returned expression.",
        "Warning"
    ),

    (
        r"\btuple\s*\([^)]*$",
        "Unclosed tuple Call",
        "tuple() call is not closed.",
        "Add ')'."
    ),

    (
        r"\bdict\s*\([^)]*$",
        "Unclosed dict Call",
        "dict() call is not closed.",
        "Add ')'."
    ),

    (
        r"\blist\s*\([^)]*$",
        "Unclosed list Call",
        "list() call is not closed.",
        "Add ')'."
    ),

    (
        r"\bfloat\s*\([^)]*$",
        "Unclosed float Call",
        "float() call is not closed.",
        "Add ')'."
    ),

    (
        r"\bbool\s*\([^)]*$",
        "Unclosed bool Call",
        "bool() call is not closed.",
        "Add ')'."
    ),

    (
        r"\bbytes\s*\([^)]*$",
        "Unclosed bytes Call",
        "bytes() call is not closed.",
        "Add ')'."
    ),

    (
        r"\bopen\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"]invalid['\"]",
        "Invalid File Mode",
        "Invalid file mode detected.",
        "Use modes such as r, w, a, rb or wb."
    )
]


def analyze_python(code):

    try:
        tree = ast.parse(code)

    except SyntaxError as e:

        return error_result(
            "python",
            "SyntaxError",
            e.msg,
            "Fix the syntax near this line.",
            e.lineno
        )

    for node in ast.walk(tree):

        if isinstance(node, ast.BinOp):

            if isinstance(
                node.op,
                (ast.Div, ast.FloorDiv, ast.Mod)
            ):

                if (
                    isinstance(node.right, ast.Constant)
                    and node.right.value == 0
                ):

                    return error_result(
                        "python",
                        "Division By Zero",
                        "The expression divides by zero.",
                        "Use a non-zero denominator.",
                        node.lineno
                    )

    found = check_patterns(
        code,
        "python",
        PYTHON_PATTERNS
    )

    return found or success_result("python")


# =========================================================
# JAVA - 50+ RULES
# =========================================================

JAVA_PATTERNS = [

    (
        r"\bprintff\s*\(",
        "Typo Error",
        "printff is not a Java output method.",
        "Use System.out.printf()."
    ),

    (
        r"\bprintf\s*\(",
        "Invalid printf Usage",
        "Java printf is accessed through System.out.",
        "Use System.out.printf()."
    ),

    (
        r"System\.out\.println\s*\([^;]*\)\s*$",
        "Missing Semicolon",
        "Java statement is missing ';'.",
        "Add ';'."
    ),

    (
        r"System\.out\.print\s*\([^;]*\)\s*$",
        "Missing Semicolon",
        "Java statement is missing ';'.",
        "Add ';'."
    ),

    (
        r"\bint\s+\w+\s*=\s*['\"]",
        "Type Mismatch",
        "String value assigned to int.",
        "Use an integer value."
    ),

    (
        r"\bboolean\s+\w+\s*=\s*\d",
        "Type Mismatch",
        "Number assigned to boolean.",
        "Use true/false."
    ),

    (
        r"\bString\s+\w+\s*=\s*\d",
        "Type Mismatch",
        "Number assigned to String.",
        "Use String.valueOf() or a numeric type."
    ),

    (
        r"\bint\s+\w+\s*=\s*null\b",
        "Null Primitive Error",
        "Primitive int cannot contain null.",
        "Use Integer if null is required."
    ),

    (
        r"\b\d+\s*/\s*0\b",
        "Division By Zero",
        "Expression divides by zero.",
        "Check the denominator."
    ),

    (
        r"\bif\s*\(\s*\)",
        "Empty If Condition",
        "if has no condition.",
        "Provide a condition."
    ),

    (
        r"\bwhile\s*\(\s*\)",
        "Empty While Condition",
        "while has no condition.",
        "Provide a condition."
    ),

    (
        r"\bswitch\s*\(\s*\)",
        "Empty Switch",
        "switch has no expression.",
        "Provide an expression."
    ),

    (
        r"\bcase\s*:",
        "Missing Case Value",
        "case requires a value.",
        "Use case value:."
    ),

    (
        r"\bdefault\s+;",
        "Invalid Default",
        "default requires ':'.",
        "Use default:."
    ),

    (
        r"\bcatch\s*\(\s*\)",
        "Empty Catch",
        "catch requires an exception.",
        "Specify exception type and variable."
    ),

    (
        r"\bthrow\s*;",
        "Invalid Throw",
        "throw requires an exception object.",
        "Throw a specific exception."
    ),

    (
        r"\bthrows\s*[\{;]",
        "Incomplete Throws",
        "throws requires an exception type.",
        "Specify the exception."
    ),

    (
        r"\bmain\s*\(\s*\)",
        "Invalid Main Method",
        "Standard Java main needs String[] args.",
        "Use public static void main(String[] args)."
    ),

    (
        r"\bclass\s+\d",
        "Invalid Class Name",
        "Class name cannot start with a number.",
        "Use a valid identifier."
    ),

    (
        r"\b(int|double|float|long|short|byte|char|boolean|String)\s+\d",
        "Invalid Variable Name",
        "Variable cannot start with a number.",
        "Use a valid identifier."
    ),

    (
        r"\bnew\s+\w+\s*\[\s*\]",
        "Missing Array Size",
        "Array creation needs a size or initializer.",
        "Provide size or initializer."
    ),

    (
        r"\b\w+\s*\[\s*-",
        "Negative Array Index",
        "Array index cannot be negative.",
        "Use a valid index."
    ),

    (
        r"\.length\s*\(\s*\)",
        "Array Length Error",
        "Arrays use length without parentheses.",
        "Use array.length."
    ),

    (
        r"\bString\s+\w+\s*==",
        "String Comparison Error",
        "== compares references, not String contents.",
        "Use .equals()."
    ),

    (
        r"['\"][^'\"]*['\"]\s*==\s*\w+",
        "String Comparison Error",
        "String contents should normally use equals().",
        "Use .equals()."
    ),

    (
        r"\bArrayList\s+\w+\s*=",
        "Raw Type Warning",
        "Raw ArrayList loses type safety.",
        "Use ArrayList<Type>.",
        "Warning"
    ),

    (
        r"\bHashMap\s+\w+\s*=",
        "Raw Type Warning",
        "Raw HashMap loses generic type safety.",
        "Use HashMap<Key,Value>.",
        "Warning"
    ),

    (
        r"\bScanner\s+\w+\s*=\s*new\s+Scanner\s*\(\s*\)",
        "Scanner Constructor Error",
        "Scanner requires an input source.",
        "Use new Scanner(System.in)."
    ),

    (
        r"\bpackage\s*;",
        "Invalid Package",
        "package requires a package name.",
        "Specify a package or remove it."
    ),

    (
        r"\bimport\s*;",
        "Invalid Import",
        "import requires a class/package.",
        "Specify what to import."
    ),

    (
        r"\bextends\s*[\{;]",
        "Incomplete Extends",
        "extends requires a parent class.",
        "Specify superclass."
    ),

    (
        r"\bimplements\s*[\{;]",
        "Incomplete Implements",
        "implements requires an interface.",
        "Specify interface."
    ),

    (
        r"\bstatic\s+static\b",
        "Duplicate Modifier",
        "static is repeated.",
        "Remove duplicate modifier."
    ),

    (
        r"\bpublic\s+public\b",
        "Duplicate Modifier",
        "public is repeated.",
        "Remove duplicate modifier."
    ),

    (
        r"\bprivate\s+private\b",
        "Duplicate Modifier",
        "private is repeated.",
        "Remove duplicate modifier."
    ),

    (
        r"\bfinal\s+final\b",
        "Duplicate Modifier",
        "final is repeated.",
        "Remove duplicate modifier."
    ),

    (
        r"\bInteger\.parseInt\s*\(\s*['\"][A-Za-z]+['\"]\s*\)",
        "Number Format Error",
        "Text cannot be converted to integer.",
        "Provide numeric text or catch NumberFormatException."
    ),

    (
        r"\bDouble\.parseDouble\s*\(\s*['\"][A-Za-z]+['\"]\s*\)",
        "Number Format Error",
        "Text may not be a valid double.",
        "Use valid numeric text."
    ),

    (
        r"\bSystem\.out\.println\s*\(\s*\w+\s*\+\s*\w+\s*\)",
        "Expression Check",
        "Check whether + is arithmetic or concatenation.",
        "Use explicit types/parentheses if required.",
        "Warning"
    ),

    (
        r"\breturn\s*;\s*$",
        "Empty Return",
        "Non-void method may require a value.",
        "Return the correct value."
    ),

    (
        r"\bif\s*\([^)]*\)\s*=",
        "Assignment In Condition",
        "A single '=' performs assignment.",
        "Use == for comparison."
    ),

    (
        r"\bnull\s*\+\s*\d+",
        "Null Arithmetic",
        "null is used in arithmetic.",
        "Check value before arithmetic."
    ),

    (
        r"\bnew\s+\w+\s*\([^)]*$",
        "Unclosed Constructor",
        "Constructor call is not closed.",
        "Add ')'."
    ),

    (
        r"\bcatch\s*\(\s*\w+\s+\)",
        "Invalid Catch Parameter",
        "Catch parameter has no variable name.",
        "Use catch(Exception e)."
    ),

    (
        r"\bthrow\s+\w+\s*$",
        "Possible Missing Semicolon",
        "throw statement appears incomplete.",
        "Complete the statement and add ';'."
    ),

    (
        r"\bfor\s*\([^)]*;[^)]*;\s*\)",
        "For Loop Check",
        "Verify initialization, condition and update.",
        "Ensure loop logic is correct.",
        "Warning"
    ),

    (
        r"\bwhile\s*\(\s*true\s*\)",
        "Possible Infinite Loop",
        "Loop is always true.",
        "Ensure a reachable break condition.",
        "Warning"
    ),

    (
        r"\bdo\s*\{",
        "Do While Check",
        "Verify that the do block ends with while(condition);.",
        "Add the required while condition.",
        "Warning"
    ),

    (
        r"\bnew\s+\w+\s*\[\s*-",
        "Negative Array Size",
        "Array size cannot be negative.",
        "Use a non-negative size."
    ),

    (
        r"\bSystem\.out\.println\s*\([^)]*$",
        "Unclosed println",
        "println call is not closed.",
        "Add ')'."
    ),

    (
        r"\bSystem\.out\.print\s*\([^)]*$",
        "Unclosed print",
        "print call is not closed.",
        "Add ')'."
    ),

    (
        r"\bScanner\s+\w+\s*=\s*new\s+Scanner\s*\(",
        "Scanner Initialization Check",
        "Verify Scanner has a valid input source.",
        "Usually use System.in.",
        "Warning"
    ),

    (
        r"\bStringBuilder\s+\w+\s*=\s*new\s+StringBuilder\s*\(\s*\)\s*;",
        "StringBuilder Check",
        "Empty StringBuilder is valid; verify intended capacity.",
        "Use a capacity if large strings are expected.",
        "Warning"
    )
]


def analyze_java(code):

    found = check_patterns(
        code,
        "java",
        JAVA_PATTERNS
    )

    return found or success_result("java")


# =========================================================
# C / C++ / JAVASCRIPT
# =========================================================
# Add their rule lists here using the same pattern:
#
# (
#   r"regex",
#   "Error Name",
#   "Reason",
#   "Fix"
# )
#
# The dispatcher below is already ready for them.
# =========================================================


def analyze_c(code):
    # Common C errors
    patterns = [

        (
            r"\bprintff\s*\(",
            "Typo Error",
            "printff is not a standard C function.",
            "Use printf()."
        ),

        (
            r"\bprintf\s*\([^;]*\)\s*$",
            "Missing Semicolon",
            "printf statement is missing ';'.",
            "Add ';'."
        ),

        (
            r"\bscanf\s*\([^;]*\)\s*$",
            "Missing Semicolon",
            "scanf statement is missing ';'.",
            "Add ';'."
        ),

        (
            r"\bvoid\s+main\s*\(",
            "Non Standard Main",
            "void main() is not standard C.",
            "Use int main()."
        ),

        (
            r"\b\d+\s*/\s*0\b",
            "Division By Zero",
            "Division by zero detected.",
            "Use a non-zero denominator."
        ),

        (
            r"\bchar\s+\w+\s*=\s*\"[^\"]*\"",
            "Character Assignment Error",
            "char cannot store a string.",
            "Use single quotes for one character."
        ),

        (
            r"\bint\s+\w+\s*=\s*\"[^\"]*\"",
            "Type Mismatch",
            "String assigned to int.",
            "Use an integer value."
        ),

        (
            r"\bgets\s*\(",
            "Unsafe gets Usage",
            "gets() can cause buffer overflow.",
            "Use fgets().",
            "Warning"
        ),

        (
            r"\bstrcpy\s*\(",
            "Unsafe strcpy Usage",
            "strcpy() can overflow destination buffer.",
            "Use safer bounded string handling.",
            "Warning"
        ),

        (
            r"\bstrcat\s*\(",
            "Unsafe strcat Usage",
            "strcat() can overflow destination buffer.",
            "Ensure sufficient destination capacity.",
            "Warning"
        ),

        (
            r"\bscanf\s*\(\s*\"[^\"]*%d[^\"]*\"\s*,\s*(?!&)",
            "scanf Missing Address",
            "scanf %d normally requires an address.",
            "Use &variable."
        ),

        (
            r"\bscanf\s*\(\s*\"[^\"]*%f[^\"]*\"\s*,\s*(?!&)",
            "scanf Missing Address",
            "scanf %f normally requires a pointer.",
            "Use &variable."
        ),

        (
            r"\bif\s*\(\s*\)",
            "Empty If Condition",
            "if has no condition.",
            "Provide a condition."
        ),

        (
            r"\bwhile\s*\(\s*\)",
            "Empty While Condition",
            "while has no condition.",
            "Provide a condition."
        ),

        (
            r"\bfor\s*\(\s*;\s*;\s*\)",
            "Empty For Loop",
            "for loop has no expressions.",
            "Add loop expressions."
        ),

        (
            r"\bswitch\s*\(\s*\)",
            "Empty Switch",
            "switch has no expression.",
            "Provide an expression."
        ),

        (
            r"\bcase\s*:",
            "Missing Case Value",
            "case requires a value.",
            "Use case value:."
        ),

        (
            r"\bdefault\s+;",
            "Invalid Default",
            "default requires ':'.",
            "Use default:."
        ),

        (
            r"\bint\s+\w+\s*\[\s*-",
            "Negative Array Size",
            "Array size cannot be negative.",
            "Use a positive size."
        ),

        (
            r"\bint\s+\*\s*\w+\s*=\s*\d+",
            "Pointer Type Error",
            "Integer assigned to pointer.",
            "Assign a valid address."
        ),

        (
            r"\bmalloc\s*\(\s*0\s*\)",
            "Zero Size Allocation",
            "malloc(0) is suspicious.",
            "Validate allocation size.",
            "Warning"
        ),

        (
            r"\bfree\s*\(\s*&",
            "Invalid free",
            "Address of a variable should not normally be passed to free().",
            "Free the allocated pointer."
        ),

        (
            r"\bif\s*\([^)]*\)\s*=\s*",
            "Assignment In Condition",
            "Single '=' performs assignment.",
            "Use == for comparison."
        ),

        (
            r"\bwhile\s*\(\s*1\s*\)",
            "Possible Infinite Loop",
            "while(1) is always true.",
            "Ensure a reachable break.",
            "Warning"
        ),

        (
            r"\bvoid\s+\w+\s*\([^)]*\)\s*\{",
            "Function Check",
            "Void function detected.",
            "Verify return logic.",
            "Warning"
        ),

        (
            r"\binclude\s*[<\"]",
            "Invalid Include",
            "Preprocessor include needs '#'.",
            "Use #include <header.h>."
        ),

        (
            r"\bsizeof\s*\(\s*\)",
            "Empty sizeof",
            "sizeof requires a type or expression.",
            "Provide a type or expression."
        ),

        (
            r"\breturn\s+\w+\s*$",
            "Missing Semicolon",
            "return statement appears incomplete.",
            "Add ';'."
        )
    ]

    found = check_patterns(code, "c", patterns)

    return found or success_result("c")


def analyze_cpp(code):

    patterns = [

        (
            r"\bprintff\s*\(",
            "Typo Error",
            "printff is not a standard C++ function.",
            "Use cout or printf()."
        ),

        (
            r"\bcout\s*<<[^;]*$",
            "Missing Semicolon",
            "cout statement is missing ';'.",
            "Add ';'."
        ),

        (
            r"\bcin\s*>>[^;]*$",
            "Missing Semicolon",
            "cin statement is missing ';'.",
            "Add ';'."
        ),

        (
            r"\bcout\s*<(?!!)",
            "Wrong Stream Operator",
            "cout uses <<.",
            "Use cout << value;"
        ),

        (
            r"\bcin\s*<(?!!)",
            "Wrong Input Operator",
            "cin uses >>.",
            "Use cin >> value;"
        ),

        (
            r"\bint\s+\w+\s*=\s*\"[^\"]*\"",
            "Type Mismatch",
            "String assigned to int.",
            "Use a numeric value."
        ),

        (
            r"\bchar\s+\w+\s*=\s*\"[^\"]*\"",
            "Character Assignment Error",
            "char cannot store a string.",
            "Use a character literal."
        ),

        (
            r"\b\d+\s*/\s*0\b",
            "Division By Zero",
            "Division by zero detected.",
            "Check denominator."
        ),

        (
            r"\bif\s*\(\s*\)",
            "Empty If Condition",
            "if has no condition.",
            "Provide a condition."
        ),

        (
            r"\bwhile\s*\(\s*\)",
            "Empty While Condition",
            "while has no condition.",
            "Provide a condition."
        ),

        (
            r"\bfor\s*\(\s*;\s*;\s*\)",
            "Empty For Loop",
            "for loop has no expressions.",
            "Add loop expressions."
        ),

        (
            r"\bswitch\s*\(\s*\)",
            "Empty Switch",
            "switch has no expression.",
            "Provide expression."
        ),

        (
            r"\bcase\s*:",
            "Missing Case Value",
            "case requires a value.",
            "Use case value:."
        ),

        (
            r"\bdefault\s+;",
            "Invalid Default",
            "default requires ':'.",
            "Use default:."
        ),

        (
            r"\bdelete\s*\(",
            "Invalid Delete Syntax",
            "delete is an operator.",
            "Use delete pointer;"
        ),

        (
            r"\bfree\s*\(\s*new\s+",
            "Mixed Memory APIs",
            "new memory should not be released with free().",
            "Use delete/delete[]."
        ),

        (
            r"\bnew\s+\w+\s*\[\s*0\s*\]",
            "Zero Size Allocation",
            "Zero-size array allocation is suspicious.",
            "Use a positive size.",
            "Warning"
        ),

        (
            r"\bNULL\b",
            "Legacy Null Pointer",
            "NULL is legacy in modern C++.",
            "Prefer nullptr.",
            "Warning"
        ),

        (
            r"\bclass\s+\d",
            "Invalid Class Name",
            "Class name cannot start with a number.",
            "Use a valid identifier."
        ),

        (
            r"\bauto\s+\w+\s*;",
            "Undeduced Auto",
            "auto needs an initializer.",
            "Initialize the variable."
        ),

        (
            r"\bstd::string\s+\w+\s*=\s*'[^']*'",
            "String Literal Error",
            "Single quotes create character literals.",
            "Use double quotes for std::string."
        ),

        (
            r"\bstrcmp\s*\([^)]*\)\s*==\s*1",
            "strcmp Logic Error",
            "strcmp is not guaranteed to return exactly 1.",
            "Compare > 0, == 0 or < 0."
        ),

        (
            r"\bstrcmp\s*\([^)]*\)\s*==\s*-1",
            "strcmp Logic Error",
            "strcmp is not guaranteed to return exactly -1.",
            "Compare < 0."
        ),

        (
            r"\bif\s*\([^)]*\)\s*=\s*",
            "Assignment In Condition",
            "Single '=' performs assignment.",
            "Use == for comparison."
        ),

        (
            r"\bwhile\s*\(\s*true\s*\)",
            "Possible Infinite Loop",
            "while(true) never ends without an exit.",
            "Ensure a break/return.",
            "Warning"
        ),

        (
            r"\bvoid\s+main\s*\(",
            "Non Standard Main",
            "void main() is not standard C++.",
            "Use int main()."
        ),

        (
            r"\bnew\s+\w+\s*;\s*$",
            "Unassigned Allocation",
            "Allocated object is not stored.",
            "Store the pointer or use a smart pointer."
        ),

        (
            r"\bvector\s*<\s*\w+\s*>\s+\w+\s*\[\s*-",
            "Negative Index",
            "Vector index cannot be negative.",
            "Use a valid index."
        )
    ]

    found = check_patterns(code, "cpp", patterns)

    return found or success_result("cpp")


def analyze_javascript(code):

    patterns = [

        (
            r"\bprintff\s*\(",
            "Typo Error",
            "printff is not a JavaScript function.",
            "Use console.log()."
        ),

        (
            r"\bprintf\s*\(",
            "Unknown Function",
            "printf is not standard browser JavaScript.",
            "Use console.log()."
        ),

        (
            r"\bconsole\.log\s*\([^)]*$",
            "Unclosed console.log",
            "console.log() is not closed.",
            "Add ')'."
        ),

        (
            r"\bif\s*\(\s*\)",
            "Empty If Condition",
            "if has no condition.",
            "Provide a condition."
        ),

        (
            r"\bwhile\s*\(\s*\)",
            "Empty While Condition",
            "while has no condition.",
            "Provide a condition."
        ),

        (
            r"\bfor\s*\(\s*;\s*;\s*\)",
            "Empty For Loop",
            "for loop has no expressions.",
            "Add loop expressions."
        ),

        (
            r"\bfunction\s+\d",
            "Invalid Function Name",
            "Function name cannot start with a number.",
            "Use a valid identifier."
        ),

        (
            r"\b(let|const|var)\s+\d",
            "Invalid Variable Name",
            "Variable cannot start with a number.",
            "Use a valid identifier."
        ),

        (
            r"\bconst\s+\w+\s*=\s*$",
            "Uninitialized Const",
            "const must have a value.",
            "Initialize the const."
        ),

        (
            r"\btrue\s*=",
            "Invalid Assignment",
            "true is a Boolean literal.",
            "Assign to a variable instead."
        ),

        (
            r"\bfalse\s*=",
            "Invalid Assignment",
            "false is a Boolean literal.",
            "Assign to a variable instead."
        ),

        (
            r"\bundefined\s*=",
            "Invalid Assignment",
            "undefined should not be assigned directly.",
            "Use a variable."
        ),

        (
            r"\bNaN\s*=",
            "Invalid Assignment",
            "NaN is a special numeric value.",
            "Do not assign to NaN."
        ),

        (
            r"\btypeof\s+\w+\s*==\s*['\"]object['\"]",
            "Null Type Check Issue",
            "typeof null returns object.",
            "Check value !== null.",
            "Warning"
        ),

        (
            r"\b\d+\s*/\s*0\b",
            "Division By Zero",
            "JavaScript produces Infinity for division by zero.",
            "Validate denominator.",
            "Warning"
        ),

        (
            r"\bJSON\.parse\s*\(\s*\)",
            "Missing JSON Input",
            "JSON.parse requires input.",
            "Provide JSON text."
        ),

        (
            r"\bdocument\.getElementById\s*\(\s*\)",
            "Missing Element ID",
            "getElementById requires an ID.",
            "Provide an element ID."
        ),

        (
            r"\bdocument\.querySelector\s*\(\s*\)",
            "Missing Selector",
            "querySelector requires a CSS selector.",
            "Provide a selector."
        ),

        (
            r"\bdocument\.querySelectorAll\s*\(\s*\)",
            "Missing Selector",
            "querySelectorAll requires a selector.",
            "Provide a selector."
        ),

        (
            r"\baddEventListener\s*\(\s*['\"][^'\"]*['\"]\s*,\s*\)",
            "Missing Event Handler",
            "addEventListener needs a callback.",
            "Provide a function."
        ),

        (
            r"\bsetTimeout\s*\(\s*\)",
            "Incomplete setTimeout",
            "setTimeout needs a callback.",
            "Provide a callback."
        ),

        (
            r"\bsetInterval\s*\(\s*\)",
            "Incomplete setInterval",
            "setInterval needs a callback.",
            "Provide a callback."
        ),

        (
            r"\bparseInt\s*\(\s*['\"][A-Za-z]+['\"]",
            "Possible NaN",
            "parseInt may return NaN.",
            "Validate the input."
        ),

        (
            r"\bparseFloat\s*\(\s*['\"][A-Za-z]+['\"]",
            "Possible NaN",
            "parseFloat may return NaN.",
            "Validate the input."
        ),

        (
            r"\.length\s*\(\s*\)",
            "Invalid length Usage",
            "JavaScript length is a property.",
            "Use value.length."
        ),

        (
            r"\bfor\s*\(\s*let\s+\w+\s*=\s*0\s*;\s*\w+\s*<=\s*\w+\.length\s*;",
            "Possible Array Out Of Bounds",
            "Index may reach array.length.",
            "Use < array.length."
        ),

        (
            r"\bif\s*\([^)]*\)\s*=\s*[^=]",
            "Assignment Instead Of Comparison",
            "Single '=' assigns a value.",
            "Use === or ==."
        ),

        (
            r"\bvar\s+",
            "Legacy var Usage",
            "var has function scope.",
            "Prefer let or const.",
            "Warning"
        ),

        (
            r"\beval\s*\(",
            "Dangerous eval Usage",
            "eval executes dynamic JavaScript.",
            "Avoid eval for untrusted input.",
            "Warning"
        ),

        (
            r"\bdocument\.write\s*\(",
            "Dangerous document.write",
            "document.write can overwrite the page.",
            "Prefer DOM methods.",
            "Warning"
        ),

        (
            r"\binnerHTML\s*=",
            "Potential XSS Sink",
            "Untrusted HTML can cause XSS.",
            "Prefer textContent or sanitize HTML.",
            "Warning"
        ),

        (
            r"\bfetch\s*\(\s*\)",
            "Missing Fetch URL",
            "fetch requires a URL.",
            "Provide an endpoint."
        ),

        (
            r"\bawait\s*$",
            "Incomplete Await",
            "await requires an expression.",
            "Await a Promise."
        ),

        (
            r"\bthrow\s*;",
            "Incomplete Throw",
            "throw requires an expression.",
            "Throw an Error."
        ),

        (
            r"\bnew\s+Error\s*\(\s*\)",
            "Empty Error Message",
            "Error has no message.",
            "Provide an error message.",
            "Warning"
        ),

        (
            r"\btry\s*\{[^}]*\}\s*(?!catch|finally)",
            "Missing Catch/Finally",
            "try needs catch or finally.",
            "Add catch or finally."
        ),

        (
            r"\bswitch\s*\(\s*\)",
            "Empty Switch",
            "switch has no expression.",
            "Provide an expression."
        ),

        (
            r"\bcase\s*:",
            "Missing Case Value",
            "case requires a value.",
            "Use case value:."
        ),

        (
            r"\breturn\s+[^;{}\n]+$",
            "Missing Semicolon",
            "return statement may need ';'.",
            "Add ';'.",
            "Warning"
        ),

        (
            r"\b(let|const|var)\s+\w+\s*=\s*[^;{}\n]+$",
            "Possible Missing Semicolon",
            "Variable declaration may be missing ';'.",
            "Add ';'.",
            "Warning"
        ),

        (
            r"\bArray\s*\(\s*-",
            "Invalid Array Size",
            "Array length cannot be negative.",
            "Use a non-negative size."
        ),

        (
            r"\bnew\s+Date\s*\(\s*['\"]invalid['\"]",
            "Invalid Date",
            "Invalid date string detected.",
            "Use a valid date."
        ),

        (
            r"\bPromise\.resolve\s*\(\s*\)",
            "Undefined Promise Value",
            "Promise resolves with undefined.",
            "Provide the intended value.",
            "Warning"
        ),

        (
            r"\bcatch\s*\(\s*\)",
            "Catch Parameter Check",
            "Catch parameter is omitted.",
            "Use catch(error) if the error object is needed.",
            "Warning"
        )
    ]

    found = check_patterns(
        code,
        "javascript",
        patterns
    )

    return found or success_result("javascript")


# =========================================================
# LANGUAGE DISPATCHER
# =========================================================

ALIASES = {

    "py": "python",
    "python3": "python",

    "js": "javascript",
    "node": "javascript",

    "c++": "cpp",
    "cc": "cpp",

    "java": "java",
    "c": "c"
}


def analyze(code, language):

    language = language.lower().strip()

    language = ALIASES.get(
        language,
        language
    )

    if not code.strip():

        return error_result(
            language,
            "Empty Code",
            "No code was provided.",
            "Enter some code."
        )

    if language == "python":
        return analyze_python(code)

    if language == "java":
        return analyze_java(code)

    if language == "c":
        return analyze_c(code)

    if language == "cpp":
        return analyze_cpp(code)

    if language == "javascript":
        return analyze_javascript(code)

    return error_result(
        language,
        "Unsupported Language",
        "This language is not configured.",
        "Select Python, Java, C, C++ or JavaScript."
    )


# =========================================================
# API
# =========================================================

@app.route("/analyze", methods=["POST"])
def analyze_route():

    try:

        data = request.get_json(silent=True) or {}

        code = data.get("code", "")
        language = data.get(
            "language",
            "python"
        )

        return jsonify(
            analyze(code, language)
        )

    except Exception as e:

        return jsonify({

            "status": "server_error",

            "error": "Analyzer Error",

            "reason": str(e),

            "fix": "Check the submitted code."

        }), 500


if __name__ == "__main__":
    app.run(debug=True)
