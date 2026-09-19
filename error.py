
from flask import Flask, request, jsonify, send_file
import ast
import re

app = Flask(__name__)


# ============================================================
# FRONTEND
# ============================================================

@app.route("/")
def home():
    return send_file("error.html")


@app.route("/error.css")
def css():
    return send_file("error.css")


@app.route("/error.js")
def js():
    return send_file("error.js")


# ============================================================
# COMMON RESULT
# ============================================================

def result(language, error, reason, fix, line,
           severity="Error", rule=None):

    return {
        "status": "error",
        "language": language,
        "severity": severity,
        "line": line,
        "rule": rule,
        "error": error,
        "reason": reason,
        "fix": fix
    }


def success(language):
    return {
        "status": "success",
        "language": language,
        "errors": [],
        "message": "No known error detected."
    }


def line_number(code, position):
    return code[:position].count("\n") + 1


def regex_scan(code, language, rules):
    """
    Detect multiple errors instead of stopping
    after the first error.
    """

    found = []

    for rule in rules:

        pattern = rule["pattern"]

        try:
            matches = re.finditer(
                pattern,
                code,
                re.IGNORECASE | re.MULTILINE
            )
        except re.error:
            continue

        for match in matches:

            line = line_number(code, match.start())

            found.append(
                result(
                    language,
                    rule["error"],
                    rule["reason"],
                    rule["fix"],
                    line,
                    rule.get("severity", "Error"),
                    rule.get("id")
                )
            )

    return found


def remove_duplicates(errors):

    unique = []
    seen = set()

    for error in errors:

        key = (
            error["language"],
            error["line"],
            error["error"]
        )

        if key not in seen:
            seen.add(key)
            unique.append(error)

    unique.sort(key=lambda x: (
        x["line"] if x["line"] else 0
    ))

    return unique


# ============================================================
# PYTHON
# ============================================================

PYTHON_RULES = [

# 01
{
"id": "PY001",
"pattern": r"\bprintff\s*",
"error": "Unknown function printff()",
"reason": "printff() is not a standard Python function.",
"fix": "Use print()."
},

# 02
{
"id": "PY002",
"pattern": r"\bprin\s*\(",
"error": "Possible typo in print()",
"reason": "prin() is not the standard Python output function.",
"fix": "Use print()."
},

# 03
{
"id": "PY003",
"pattern": r"\bif\s+[^:\n]+$",
"error": "Missing colon after if",
"reason": "Python if statements require a colon.",
"fix": "Add : at the end of the if condition."
},

# 04
{
"id": "PY004",
"pattern": r"\belse\s*$",
"error": "Missing colon after else",
"reason": "Python else statements require a colon.",
"fix": "Write else:."
},

# 05
{
"id": "PY005",
"pattern": r"\belif\s+[^:\n]+$",
"error": "Missing colon after elif",
"reason": "elif requires a colon.",
"fix": "Add : after the elif condition."
},

# 06
{
"id": "PY006",
"pattern": r"\bfor\s+[^:\n]+$",
"error": "Missing colon after for",
"reason": "Python for loops require a colon.",
"fix": "Add : at the end of the for statement."
},

# 07
{
"id": "PY007",
"pattern": r"\bwhile\s+[^:\n]+$",
"error": "Missing colon after while",
"reason": "Python while loops require a colon.",
"fix": "Add :."
},

# 08
{
"id": "PY008",
"pattern": r"\bdef\s+\w+\s*\([^)]*\s*$",
"error": "Missing colon after function definition",
"reason": "Function definitions require a colon.",
"fix": "Add : after the function declaration."
},

# 09
{
"id": "PY009",
"pattern": r"\bclass\s+\w+\s*$",
"error": "Missing colon after class",
"reason": "Class definitions require a colon.",
"fix": "Add : after the class declaration."
},

# 10
{
"id": "PY010",
"pattern": r"\btry\s*$",
"error": "Missing colon after try",
"reason": "try requires a colon.",
"fix": "Use try:."
},

# 11
{
"id": "PY011",
"pattern": r"\bexcept(?:\s+[^:]*)?$",
"error": "Missing colon after except",
"reason": "except requires a colon.",
"fix": "Add : after except."
},

# 12
{
"id": "PY012",
"pattern": r"\bfinally\s*$",
"error": "Missing colon after finally",
"reason": "finally requires a colon.",
"fix": "Use finally:."
},

# 13
{
"id": "PY013",
"pattern": r"\bwith\s+[^:\n]+$",
"error": "Missing colon after with",
"reason": "with statements require a colon.",
"fix": "Add :."
},

# 14
{
"id": "PY014",
"pattern": r"\bimport\s+[A-Za-z_]\w*\s+from\b",
"error": "Invalid import syntax",
"reason": "import and from are used differently.",
"fix": "Use from module import name."
},

# 15
{
"id": "PY015",
"pattern": r"\bfrom\s+\w+\s+import\s*$",
"error": "Missing imported name",
"reason": "from ... import requires a name.",
"fix": "Specify what should be imported."
},

# 16
{
"id": "PY016",
"pattern": r"\bprint\s+[^(]",
"error": "Possible Python 2 print syntax",
"reason": "Python 3 uses print() as a function.",
"fix": "Use print(value)."
},

# 17
{
"id": "PY017",
"pattern": r"\bTrue\s*=\s*",
"error": "Cannot assign to True",
"reason": "True is a Python constant.",
"fix": "Use another variable name."
},

# 18
{
"id": "PY018",
"pattern": r"\bFalse\s*=\s*",
"error": "Cannot assign to False",
"reason": "False is a Python constant.",
"fix": "Use another variable name."
},

# 19
{
"id": "PY019",
"pattern": r"\bNone\s*=\s*",
"error": "Cannot assign to None",
"reason": "None is a Python constant.",
"fix": "Use another variable name."
},

# 20
{
"id": "PY020",
"pattern": r"\bif\s+.*[^=!<>]=[^=].*:",
"error": "Assignment used in condition",
"reason": "Python conditions normally use == for comparison.",
"fix": "Use == instead of =."
},

# 21
{
"id": "PY021",
"pattern": r"\bfor\s+\w+\s+in\s+range\s*\s*\d+\s*,\s*\d+\s*\s*$",
"error": "Possible incomplete for loop",
"reason": "The loop appears to have no body.",
"fix": "Add an indented loop body."
},

# 22
{
"id": "PY022",
"pattern": r"\bwhile\s+True\s*:",
"error": "Potential infinite loop",
"reason": "while True continues until break or exception.",
"fix": "Ensure a valid break condition exists.",
"severity": "Warning"
},

# 23
{
"id": "PY023",
"pattern": r"\bopen\s*[^)]*",
"error": "Check file handling",
"reason": "Files should normally be closed after use.",
"fix": "Prefer using with open(...) as file:.",
"severity": "Warning"
},

# 24
{
"id": "PY024",
"pattern": r"\b\d+\s*/\s*0\b",
"error": "Division by zero",
"reason": "Division by zero raises an exception.",
"fix": "Check the denominator before division."
},

# 25
{
"id": "PY025",
"pattern": r"\bint\s*\s*input\s*\([^)]*\s*\)",
"error": "Check user input conversion",
"reason": "Invalid numeric input can raise ValueError.",
"fix": "Validate input or handle ValueError.",
"severity": "Warning"
},

# 26
{
"id": "PY026",
"pattern": r"\bfloat\s*\s*input\s*\([^)]*\s*\)",
"error": "Check float input conversion",
"reason": "Non-numeric input can raise ValueError.",
"fix": "Validate input or use try-except.",
"severity": "Warning"
},

# 27
{
"id": "PY027",
"pattern": r"\blist\s*[^]+\]",
"error": "Check list index",
"reason": "Invalid indexes can raise IndexError.",
"fix": "Ensure the index is within the list length.",
"severity": "Warning"
},

# 28
{
"id": "PY028",
"pattern": r"\.append\s*[^)]*\s*\.",
"error": "Invalid append chaining",
"reason": "append() returns None.",
"fix": "Do not chain methods after append()."
},

# 29
{
"id": "PY029",
"pattern": r"\.sort\s*\s*\s*\.",
"error": "Invalid sort chaining",
"reason": "list.sort() modifies the list and returns None.",
"fix": "Call sort() separately."
},

# 30
{
"id": "PY030",
"pattern": r"\bprint\s*[^)]*\s*\+\s*",
"error": "Invalid print expression",
"reason": "Check the expression being concatenated with print().",
"fix": "Build the expression before passing it to print().",
"severity": "Warning"
},

# 31
{
"id": "PY031",
"pattern": r"\bdef\s+\w+\s*[^)]*\s*:",
"error": "Check function parameters",
"reason": "Verify that arguments passed to this function match its parameters.",
"fix": "Check function definition and function calls.",
"severity": "Info"
},

# 32
{
"id": "PY032",
"pattern": r"\breturn\s+",
"error": "Check return path",
"reason": "Functions should return appropriate values on required paths.",
"fix": "Verify the function's return value.",
"severity": "Warning"
},

# 33
{
"id": "PY033",
"pattern": r"\bexcept\s*:",
"error": "Broad exception handler",
"reason": "Catching every exception can hide programming errors.",
"fix": "Catch the specific exception you expect.",
"severity": "Warning"
},

# 34
{
"id": "PY034",
"pattern": r"\bexcept\s+Exception\s*:",
"error": "Broad Exception handler",
"reason": "Exception catches many unrelated errors.",
"fix": "Catch a more specific exception.",
"severity": "Warning"
},

# 35
{
"id": "PY035",
"pattern": r"\bglobal\s+\w+",
"error": "Global variable usage",
"reason": "Global state can make code harder to maintain.",
"fix": "Prefer function parameters or return values.",
"severity": "Warning"
},

# 36
{
"id": "PY036",
"pattern": r"\bexec\s*",
"error": "Use of exec()",
"reason": "exec() dynamically executes code.",
"fix": "Avoid exec() unless it is genuinely required.",
"severity": "Warning"
},

# 37
{
"id": "PY037",
"pattern": r"\beval\s*\(",
"error": "Use of eval()",
"reason": "eval() dynamically evaluates code.",
"fix": "Avoid eval() and parse input safely.",
"severity": "Warning"
},

# 38
{
"id": "PY038",
"pattern": r"\bos\.system\s*\(",
"error": "System command execution",
"reason": "os.system() executes an operating-system command.",
"fix": "Use safer APIs and validate inputs.",
"severity": "Warning"
},

# 39
{
"id": "PY039",
"pattern": r"\bopen\s*\([^,]+,\s*[\"']w[\"']\s*",
"error": "File opened in write mode",
"reason": "Write mode can replace existing file contents.",
"fix": "Use append mode or another mode if replacement is not intended.",
"severity": "Warning"
},

# 40
{
"id": "PY040",
"pattern": r"\b\d+\s*\s*\d+\s*",
"error": "Invalid numeric indexing",
"reason": "Integer values cannot normally be indexed.",
"fix": "Index a sequence such as a list or string.",
"severity": "Error"
},

# 41
{
"id": "PY041",
"pattern": r"\b[a-zA-Z_]\w*\s*\.\s*length\b",
"error": "Possible incorrect length property",
"reason": "Python sequences normally use len().",
"fix": "Use len(variable)."
},

# 42
{
"id": "PY042",
"pattern": r"\b[a-zA-Z_]\w*\.length\s*",
"error": "Invalid length() method",
"reason": "Python uses len() instead of length().",
"fix": "Use len(variable)."
},

# 43
{
"id": "PY043",
"pattern": r"\bnull\b",
"error": "Invalid null keyword",
"reason": "Python uses None instead of null.",
"fix": "Replace null with None."
},

# 44
{
"id": "PY044",
"pattern": r"\btrue\b",
"error": "Invalid boolean literal",
"reason": "Python boolean literal is True.",
"fix": "Use True."
},

# 45
{
"id": "PY045",
"pattern": r"\bfalse\b",
"error": "Invalid boolean literal",
"reason": "Python boolean literal is False.",
"fix": "Use False."
},

# 46
{
"id": "PY046",
"pattern": r"//",
"error": "Possible invalid comment syntax",
"reason": "Python normally uses # for comments.",
"fix": "Use # for a Python comment.",
"severity": "Warning"
},

# 47
{
"id": "PY047",
"pattern": r"\+\+",
"error": "Invalid ++ operator",
"reason": "Python does not support the C/Java ++ operator.",
"fix": "Use variable += 1."
},

# 48
{
"id": "PY048",
"pattern": r"--",
"error": "Invalid -- operator",
"reason": "Python does not support the C/Java -- operator.",
"fix": "Use variable -= 1."
},

# 49
{
"id": "PY049",
"pattern": r"\bnew\s+\w+",
"error": "Invalid new keyword",
"reason": "Python does not use new for normal object creation.",
"fix": "Create the object using ClassName()."
},

# 50
{
"id": "PY050",
"pattern": r"\bSystem\.out\.println",
"error": "Java syntax inside Python",
"reason": "System.out.println() is Java syntax.",
"fix": "Use print() in Python."
},

# 51
{
"id": "PY051",
"pattern": r"\bpublic\s+class\b",
"error": "Java class syntax detected",
"reason": "public class is Java syntax.",
"fix": "Use Python class syntax: class ClassName:."
},

# 52
{
"id": "PY052",
"pattern": r"\bString\s+\w+",
"error": "Java type declaration detected",
"reason": "Python does not require String type declarations.",
"fix": "Use variable = value."
},

# 53
{
"id": "PY053",
"pattern": r"\bint\s+\w+\s*=",
"error": "C/Java style declaration",
"reason": "Python does not use int before variable assignment.",
"fix": "Use variable = value."
},

# 54
{
"id": "PY054",
"pattern": r"\bnew\s+\w+\s*\(",
"error": "Java/C++ style object creation",
"reason": "Python does not use new.",
"fix": "Use ClassName()."
},

# 55
{
"id": "PY055",
"pattern": r"\bcatch\s*\(",
"error": "Invalid catch syntax",
"reason": "Python uses except instead of catch.",
"fix": "Use try: ... except:."
},

# 56
{
"id": "PY056",
"pattern": r"\bthrows\b",
"error": "Invalid throws keyword",
"reason": "Python does not use Java's throws declaration.",
"fix": "Handle exceptions using try-except."
},

# 57
{
"id": "PY057",
"pattern": r"\bSystem\.out",
"error": "Java output syntax",
"reason": "System.out is Java syntax.",
"fix": "Use print()."
},

# 58
{
"id": "PY058",
"pattern": r"\b&&\b",
"error": "Invalid logical operator",
"reason": "Python uses and instead of &&.",
"fix": "Replace && with and."
},

# 59
{
"id": "PY059",
"pattern": r"\|\|",
"error": "Invalid logical operator",
"reason": "Python uses or instead of ||.",
"fix": "Replace || with or."
},

# 60
{
"id": "PY060",
"pattern": r"!\s*(?!=)",
"error": "Invalid logical NOT syntax",
"reason": "Python uses not instead of !.",
"fix": "Replace ! with not."
}

]


def analyze_python(code):

    errors = regex_scan(code, "Python", PYTHON_RULES)

    # Real Python parser
    try:
        ast.parse(code)

    except SyntaxError as e:

        errors.append(
            result(
                "Python",
                "Python SyntaxError",
                e.msg,
                "Fix the syntax near the reported line.",
                e.lineno,
                "Error",
                "PY-AST"
            )
        )

    # AST checks
    try:

        tree = ast.parse(code)

        for node in ast.walk(tree):

            # Division by zero
            if isinstance(node, ast.BinOp):

                if isinstance(node.op, (
                    ast.Div,
                    ast.FloorDiv,
                    ast.Mod
                )):

                    if isinstance(node.right, ast.Constant):
                        if node.right.value == 0:

                            errors.append(
                                result(
                                    "Python",
                                    "Division by zero",
                                    "The expression divides by zero.",
                                    "Check the denominator before division.",
                                    node.lineno,
                                    "Error",
                                    "PY-AST-DIV0"
                                )
                            )

            # Bare except
            if isinstance(node, ast.ExceptHandler):

                if node.type is None:

                    errors.append(
                        result(
                            "Python",
                            "Bare except block",
                            "This catches every exception.",
                            "Catch a specific exception type.",
                            node.lineno,
                            "Warning",
                            "PY-AST-EXCEPT"
                        )
                    )

    except Exception:
        pass

    return remove_duplicates(errors)


# ============================================================
# JAVA
# ============================================================

JAVA_RULES = [

# 01
{"id":"JAVA001","pattern":r"\bprintff\s*\(","error":"Invalid printff()","reason":"printff() is not a standard Java method.","fix":"Use System.out.printf()."},

# 02
{"id":"JAVA002","pattern":r"\bSystem\.out\.prntln\s*\(","error":"Typo in println()","reason":"prntln() does not exist.","fix":"Use System.out.println()."},

# 03
{"id":"JAVA003","pattern":r"\bSystem\.out\.pritnln\s*\(","error":"Typo in println()","reason":"pritnln() does not exist.","fix":"Use System.out.println()."},

# 04
{"id":"JAVA004","pattern":r"\bSystem\.out\.println\s*\([^;\n]*\s*$","error":"Possible missing semicolon","reason":"Java statements normally end with ;.","fix":"Add ; after println()."},

# 05
{"id":"JAVA005","pattern":r"\bSystem\.out\.print\s*[^;\n]*\s*$","error":"Possible missing semicolon","reason":"Java statements normally end with ;.","fix":"Add ; after print()."},

# 06
{"id":"JAVA006","pattern":r"\bif\s*[^)]*(?<![=!<>])=(?!=)[^)]*","error":"Assignment in condition","reason":"= performs assignment.","fix":"Use == for comparison."},

# 07
{"id":"JAVA007","pattern":r"\bwhile\s*[^)]*(?<![=!<>])=(?!=)[^)]*","error":"Assignment in while condition","reason":"= performs assignment.","fix":"Use == for comparison."},

# 08
{"id":"JAVA008","pattern":r"\bString\s+\w+\s*==\s*","error":"String compared with ==","reason":"== compares references.","fix":"Use .equals() for String content comparison."},

# 09
{"id":"JAVA009","pattern":r"\bboolean\s+\w+\s*=\s*(?:0|1)\s*;","error":"Invalid boolean value","reason":"Java boolean uses true or false.","fix":"Use true or false."},

# 10
{"id":"JAVA010","pattern":r"\bint\s+\w+\s*=\s*\"","error":"Type mismatch","reason":"String cannot be assigned to int.","fix":"Use an integer or Integer.parseInt()."},

# 11
{"id":"JAVA011","pattern":r"\bdouble\s+\w+\s*=\s*\"","error":"Type mismatch","reason":"String cannot directly become double.","fix":"Use Double.parseDouble()."},

# 12
{"id":"JAVA012","pattern":r"\bint\s+\w+\s*=\s*\d+\.\d+\s*;","error":"Narrowing conversion","reason":"Decimal value cannot automatically become int.","fix":"Use int casting or a suitable integer value."},

# 13
{"id":"JAVA013","pattern":r"\bchar\s+\w+\s*=\s*\"[^\"']*\"\s*;","error":"Invalid char assignment","reason":"char uses single quotes.","fix":"Use char c = 'A';"},

# 14
{"id":"JAVA014","pattern":r"\bpublic\s+void\s+main\s*","error":"Invalid main method","reason":"main must be static.","fix":"Use public static void main(String[] args)."},

# 15
{"id":"JAVA015","pattern":r"\bprivate\s+static\s+void\s+main\s*\(","error":"Invalid main access","reason":"JVM expects main to be public.","fix":"Use public static void main(String[] args)."},

# 16
{"id":"JAVA016","pattern":r"\bpublic\s+static\s+int\s+main\s*\(","error":"Invalid main return type","reason":"Java main normally returns void.","fix":"Use void."},

# 17
{"id":"JAVA017","pattern":r"\belse\s*\(","error":"Invalid else condition","reason":"else cannot directly contain a condition.","fix":"Use else if (...)."},

# 18
{"id":"JAVA018","pattern":r"\bif\s*\([^)]*\s*;","error":"Empty if statement","reason":"The if statement has an empty body.","fix":"Remove ; or add a body.","severity":"Warning"},

# 19
{"id":"JAVA019","pattern":r"\bwhile\s*\s*true\s*","error":"Potential infinite loop","reason":"while(true) does not naturally terminate.","fix":"Add a valid break condition.","severity":"Warning"},

# 20
{"id":"JAVA020","pattern":r"\bfor\s*\s*;\s*;\s*","error":"Infinite for loop","reason":"The loop has no condition.","fix":"Add a termination condition.","severity":"Warning"},

# 21
{"id":"JAVA021","pattern":r"\.length\s*\s*","error":"Possible array length error","reason":"Arrays use .length, not .length().","fix":"Use array.length."},

# 22
{"id":"JAVA022","pattern":r"\.length\b","error":"Check length usage","reason":"Strings use length(), arrays use length.","fix":"Use the correct form for your data type.","severity":"Info"},

# 23
{"id":"JAVA023","pattern":r"\bString\s+\w+\s*=\s*null\s*;","error":"Possible NullPointerException","reason":"The String is null.","fix":"Check for null before calling methods.","severity":"Warning"},

# 24
{"id":"JAVA024","pattern":r"\b\w+\s*=\s*null\s*;","error":"Possible null reference","reason":"The reference may later cause NullPointerException.","fix":"Validate the object before using it.","severity":"Warning"},

# 25
{"id":"JAVA025","pattern":r"\bnew\s+Scanner\s*","error":"Check Scanner import","reason":"Scanner requires java.util.Scanner.","fix":"Add import java.util.Scanner; if needed.","severity":"Warning"},

# 26
{"id":"JAVA026","pattern":r"\bnextInt\s*\(\s*\s*;","error":"Scanner input mismatch risk","reason":"nextInt() fails if the entered value is not an integer.","fix":"Validate input or handle InputMismatchException.","severity":"Warning"},

# 27
{"id":"JAVA027","pattern":r"\bnextDouble\s*\s*\s*;","error":"Scanner input mismatch risk","reason":"nextDouble() requires numeric input.","fix":"Validate input or handle InputMismatchException.","severity":"Warning"},

# 28
{"id":"JAVA028","pattern":r"\bcatch\s*\s*Exception\s+\w+\s*","error":"Broad exception handling","reason":"Exception catches many unrelated problems.","fix":"Catch the specific exception.","severity":"Warning"},

# 29
{"id":"JAVA029","pattern":r"\bcatch\s*\s*Throwable\s+\w+\s*","error":"Very broad exception handling","reason":"Throwable includes serious JVM errors.","fix":"Catch only the expected exception.","severity":"Warning"},

# 30
{"id":"JAVA030","pattern":r"\bthrow\s+new\s+Exception\s*","error":"Generic Exception thrown","reason":"Generic Exception provides little information.","fix":"Prefer a specific exception type.","severity":"Warning"},

# 31
{"id":"JAVA031","pattern":r"\bString\s+\w+\s*=\s*new\s+String\s*\(","error":"Unnecessary String object","reason":"String literals are normally preferable.","fix":"Use a String literal when possible.","severity":"Warning"},

# 32
{"id":"JAVA032","pattern":r"\bInteger\.parseInt\s*\(\s*\"[^\"]*\"\s*","error":"Check integer conversion","reason":"Invalid numeric text causes NumberFormatException.","fix":"Validate the input before parsing.","severity":"Warning"},

# 33
{"id":"JAVA033","pattern":r"\bDouble\.parseDouble\s*\s*\"[^\"]*\"\s*","error":"Check double conversion","reason":"Invalid text causes NumberFormatException.","fix":"Validate the input.","severity":"Warning"},

# 34
{"id":"JAVA034","pattern":r"\bArrayIndexOutOfBoundsException\b","error":"Array index exception mentioned","reason":"An invalid array index can cause this exception.","fix":"Check that index >= 0 and index < array.length.","severity":"Warning"},

# 35
{"id":"JAVA035","pattern":r"\bNullPointerException\b","error":"NullPointerException mentioned","reason":"Null references can cause runtime failures.","fix":"Check objects for null before dereferencing.","severity":"Warning"},

# 36
{"id":"JAVA036","pattern":r"\b\d+\s*/\s*0\b","error":"Division by zero","reason":"Integer division by zero throws ArithmeticException.","fix":"Check denominator before division."},

# 37
{"id":"JAVA037","pattern":r"\b\d+\s*%\s*0\b","error":"Modulo by zero","reason":"Modulo by zero throws ArithmeticException.","fix":"Ensure divisor is not zero."},

# 38
{"id":"JAVA038","pattern":r"\bfinal\s+\w+\s+\w+\s*=\s*[^;]+;.*\b\w+\s*=","error":"Possible final variable reassignment","reason":"final variables cannot be reassigned.","fix":"Do not assign a new value to a final variable."},

# 39
{"id":"JAVA039","pattern":r"\bthis\s*\.\s*this\b","error":"Invalid this usage","reason":"this refers to the current object.","fix":"Use this.field or this.method()."},

# 40
{"id":"JAVA040","pattern":r"\bsuper\s*\.\s*super\b","error":"Invalid super usage","reason":"super cannot be chained this way.","fix":"Use super.field or super.method()."},

# 41
{"id":"JAVA041","pattern":r"\bimplements\s+\w+\s*\{","error":"Check interface implementation","reason":"A class implementing an interface must implement required methods unless abstract.","fix":"Implement all required interface methods."},

# 42
{"id":"JAVA042","pattern":r"\bextends\s+\w+\s*,\s*\w+","error":"Multiple class inheritance","reason":"Java classes cannot extend multiple classes.","fix":"Extend one class and use interfaces for multiple inheritance of type."},

# 43
{"id":"JAVA043","pattern":r"\bpublic\s+class\s+\w+\s+extends\s+\w+\s+extends\b","error":"Multiple extends declarations","reason":"A Java class can extend only one class.","fix":"Remove the second extends."},

# 44
{"id":"JAVA044","pattern":r"\babstract\s+final\s+class\b","error":"Invalid abstract final class","reason":"An abstract class is intended for inheritance while final prevents inheritance.","fix":"Remove either abstract or final."},

# 45
{"id":"JAVA045","pattern":r"\bprivate\s+abstract\b","error":"Invalid private abstract member","reason":"Private methods cannot be overridden by subclasses.","fix":"Use an appropriate access modifier."},

# 46
{"id":"JAVA046","pattern":r"\bstatic\s+this\b","error":"Invalid static this usage","reason":"static context does not have an instance this reference.","fix":"Use an object reference or remove static."},

# 47
{"id":"JAVA047","pattern":r"\bstatic\s+super\b","error":"Invalid static super usage","reason":"super is an instance reference.","fix":"Use super inside an instance context."},

# 48
{"id":"JAVA048","pattern":r"\bnew\s+\w+\s*\s*-",
"error":"Negative array size",
"reason":"Array size cannot be negative.",
"fix":"Use a non-negative array size."
},

# 49
{"id":"JAVA049","pattern":r"\bcase\s+[^:]+;",
"error":"Possible invalid switch case",
"reason":"switch case labels normally use a colon.",
"fix":"Use case value:."
},

# 50
{"id":"JAVA050","pattern":r"\bdefault\s*;",
"error":"Invalid switch default",
"reason":"default normally requires a colon.",
"fix":"Use default:."
},

# 51
{"id":"JAVA051","pattern":r"\bbreak\s*;\s*break\s*;",
"error":"Duplicate break",
"reason":"The second break may be unreachable or unnecessary.",
"fix":"Check the switch/loop logic.",
"severity":"Warning"
},

# 52
{"id":"JAVA052","pattern":r"\bcontinue\s*;\s*continue\s*;",
"error":"Duplicate continue",
"reason":"The second continue may be unreachable.",
"fix":"Check loop logic.",
"severity":"Warning"
},

# 53
{"id":"JAVA053","pattern":r"\bimport\s+java\.util\.scanner\b",
"error":"Incorrect Scanner import",
"reason":"Java package names are case-sensitive.",
"fix":"Use import java.util.Scanner;"
},

# 54
{"id":"JAVA054","pattern":r"\bSystem\.out\.Println\b",
"error":"Incorrect println capitalization",
"reason":"Java method names are case-sensitive.",
"fix":"Use System.out.println()."
},

# 55
{"id":"JAVA055","pattern":r"\bSystem\.Out\b",
"error":"Incorrect System.out capitalization",
"reason":"Java identifiers are case-sensitive.",
"fix":"Use System.out."
},

# 56
{"id":"JAVA056","pattern":r"\bString\.length\s*\(\s*",
"error":"Invalid String length usage",
"reason":"length() belongs to a String object, not the String class.",
"fix":"Call text.length()."
},

# 57
{"id":"JAVA057","pattern":r"\bString\.charAt\s*","error":"Invalid static charAt usage","reason":"charAt() is an instance method.","fix":"Use text.charAt(index)."},

# 58
{"id":"JAVA058","pattern":r"\bMath\.random\s*\(\s*\s*==\s*","error":"Random comparison check","reason":"Math.random() returns a double in the range [0,1).","fix":"Check the intended probability/range.","severity":"Warning"},

# 59
{"id":"JAVA059","pattern":r"\bpublic\s+class\s+\w+\s*\{[\s\S]*\bpublic\s+class\b","error":"Multiple public classes","reason":"A Java source file normally has at most one public top-level class.","fix":"Move additional public classes to separate files or remove public."},

# 60
{"id":"JAVA060","pattern":r"\bSystem\.out\.println\s*\s*;","error":"Empty println",
"reason":"println() prints only a newline.",
"fix":"Add a value if output is intended.",
"severity":"Warning"}
]


def analyze_java(code):

    errors = regex_scan(code, "Java", JAVA_RULES)

    # Basic brace balance
    if code.count("{") != code.count("}"):

        errors.append(
            result(
                "Java",
                "Unbalanced curly braces",
                "Opening and closing braces do not match.",
                "Check { and } in the code.",
                None,
                "Error",
                "JAVA-BRACES"
            )
        )

    if code.count("(") != code.count(")"):

        errors.append(
            result(
                "Java",
                "Unbalanced parentheses",
                "Opening and closing parentheses do not match.",
                "Check ( and ) in the code.",
                None,
                "Error",
                "JAVA-PAREN"
            )
        )

    if code.count("[") != code.count("]"):

        errors.append(
            result(
                "Java",
                "Unbalanced square brackets",
                "Opening and closing square brackets do not match.",
                "Check [ and ].",
                None,
                "Error",
                "JAVA-BRACKET"
            )
        )

    return remove_duplicates(errors)


# ============================================================
# C
# ============================================================

C_RULES = [

# 01
{"id":"C001","pattern":r"\bprintff\s*","error":"Unknown function printff()","reason":"printff() is not a standard C function.","fix":"Use printf()."},

# 02
{"id":"C002","pattern":r"\bscanf\s*\([^;]*\s*$","error":"Possible missing semicolon","reason":"C statements normally end with ;.","fix":"Add ; after scanf()."},

# 03
{"id":"C003","pattern":r"\bprintf\s*[^;]*\s*$","error":"Possible missing semicolon","reason":"C statements normally end with ;.","fix":"Add ; after printf()."},

# 04
{"id":"C004","pattern":r"\bif\s*[^)]*(?<![=!<>])=(?!=)[^)]*","error":"Assignment inside if","reason":"= assigns a value.","fix":"Use == for comparison."},

# 05
{"id":"C005","pattern":r"\bwhile\s*[^)]*(?<![=!<>])=(?!=)[^)]*","error":"Assignment inside while","reason":"= performs assignment.","fix":"Use == for comparison."},

# 06
{"id":"C006","pattern":r"\bint\s+\w+\s*=\s*\"","error":"Type mismatch","reason":"A string literal cannot be assigned to int.","fix":"Use an integer value."},

# 07
{"id":"C007","pattern":r"\bfloat\s+\w+\s*=\s*\"","error":"Type mismatch","reason":"A string literal cannot be assigned to float.","fix":"Use a numeric value."},

# 08
{"id":"C008","pattern":r"\bdouble\s+\w+\s*=\s*\"","error":"Type mismatch","reason":"A string literal cannot be assigned to double.","fix":"Use a numeric value."},

# 09
{"id":"C009","pattern":r"\bchar\s+\w+\s*=\s*\"[^\"']*\"\s*;","error":"Possible char/string mismatch","reason":"A char normally contains one character.","fix":"Use single quotes, for example char c = 'A';"},

# 10
{"id":"C010","pattern":r"\bvoid\s+main\s*","error":"Non-standard main declaration","reason":"void main() is not the standard C main signature.","fix":"Use int main()."},

# 11
{"id":"C011","pattern":r"\bmain\s*\(\s*void\s*\s*\{","error":"Check main return type","reason":"Standard C programs normally use int main().","fix":"Use int main(void).","severity":"Warning"},

# 12
{"id":"C012","pattern":r"\bprintf\s*\s*\"[^\"]*\"\s*","error":"Check printf statement","reason":"Verify that the printf statement is terminated correctly.","fix":"Add ; if missing.","severity":"Info"},

# 13
{"id":"C013","pattern":r"\bscanf\s*\s*\"[^\"]*\"\s*,\s*\w+\s*","error":"Possible scanf address error","reason":"scanf usually requires an address for ordinary variables.","fix":"Use &variable for int, float, etc., where appropriate.","severity":"Warning"},

# 14
{"id":"C014","pattern":r"\bscanf\s*[^&]*,\s*\w+\s*","error":"Possible missing & in scanf","reason":"scanf generally needs the address of the variable.","fix":"Use &variable for scalar input."},


{
    "id": "C015",
    "pattern": r'\bprintf\s*\(\s*"[^"]*"\s*\)',
    "message": "printf() statement detected",
    "reason": "This is a normal printf statement.",
    "fix": "Check the format string and arguments."
},
