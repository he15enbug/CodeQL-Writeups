# CodeQL
- [Documentation](https://codeql.github.com/docs/)
## Background
- Refer to [CodeQL zero to hero part 1: the fundamentals of static analysis for vulnerability research] (https://github.blog/2023-03-31-codeql-zero-to-hero-part-1-the-fundamentals-of-static-analysis-for-vulnerability-research/)
### Vulnerability detection - sources and sinks
- There are many types of vulnerabilities - some are easier to find with static analysis, some with other means, and some can only be find through manual analysis. One of the types of vulnerabilities that static analysis can find are injection vulnerabilities
- The main cause of injection vulnerabilities is untrusted, user-controlled input being used in sensitive or dangerous functions of the program. We use terms such as *data flow*, *sources*, and *sinks* to represent these in static analysis
- *Sources*: the origin of data, where user input comes from, generally the entry points to an application, e.g., HTTP GET request parameters
- *Sinks*: dangerous functions that should not be called with unsanitized untrusted data, e.g., `MySQLCursor.execute()` from the MySQLdb library in Python or the built-in function `eval()` in Python. Sinks are potentially dangerous, but they are not always immediately exploitable. Many sinks have ways of using them safely
- For a vulnerability to be present, the unsafe, user-controlled input has to be used without proper sanitization or validation in a dangerous function, i.e., there has to be a code path between the source and the sink, in which case we say that data flows from a source to a sink
### Finding sources and sinks
- We could do so manually by using the `*nix` utility `grep`, and start by searching for sources such as GET requests, e.g., look for all places in the codebase, in which GET requests are accessed
    - Problems
        1. `grep` will also match some innocuous function names and comments (False Positives)
        2. we can only search for one type of sources and review it one at a time
    - The earliest static analysis tools for security review were designed to solve these problems
### Early static analysis tools - lexical pattern matching
- Many of the steps taken by a static analysis tools are similar to the ones of a compiler or interpreter. Compilers and interpreters already perform a form of static analysis: type checking. We could adapt technologies in compilers to use in static analysis for security review
- The first problem with `grep` was that it returns results from comments and function names. We can easily filter out these results with *lexical analysis* - a well-known compiler technology. Lexical analysis reads the source code and transforms it from a stream of characters into a stream of tokens, ignoring any characters that do not contribute to the semantics of the code. Tokens consists of characters, for example, a comma, literals; for example, strings and integers or the reserved words in the language; for example, `with`, `def` in Python
- Another important feature that was introduced in static analysis tools at that time was a knowledge base containing information about dangerous sinks, and matched the sink name from the tokens. Upon match, the information about the dangerous sink and why it might be dangerous to use was displayed
- We solved the first problem. Now, we can detect sources and sinks automatically without too many false positives. The second problem still stands though - tools report on dangerous sinks, which might not have been used with untrusted data or in a way causing a vulnerability (still many false positives)
- An obvious solution is to check whether there is a connection between a source and sink
### Syntactic pattern matching, abstract syntax tree, and control flow graph
- The earliest static analysis tools leveraged lexical analysis. One of the ways to increase percision of detecting vulnerabilities is via leveraging more techniques common in compiler theory, such as parsing and abstract syntax trees (AST). One of the most popular static analysis methods: *data flow analysis with taint analysis*
- After the code is scanned for tokens, it can be built into a more abstract representation that will make it easier to query the code. One of the common approaches is to parse the code into a [parse tree](https://en.wikipedia.org/wiki/Parse_tree) and build an [abstract syntax tree](https://en.wikipedia.org/wiki/Abstract_syntax_tree)
- An AST is a tree representation of source code, in which each node has a type that it represents and that allows us to take into account the semantics. Example: one type could be a call to a method, which would be represented as a node in the tree, and its qualifier and arguments will be represented as child nodes. AST makes it easier to query the code for what we need in an analysis
- *Example*
    - Code
        ```
        1. from django.db import connection
        2. 
        3. def show_user(request, username):
        4.     with connection.cursor() as cursor:
        5.         cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)
        ```
    - AST (simplified version)
        ```
        Module
        |
        |---- ImportFrom, on line 1
        |     |
        |     +---- alias, on line 1
        |
        +---- FunctionDef, on line 3, show_user
              |
              |---- arguments
              |     |
              |     |---- arg, on line 3, request
              |     |
              |     +---- arg, on line 3, username
              |
              +---- With, on line 4
                    |
                    |---- withitem
                    |     |
                    |     |---- Call, on line 4
                    |     |     |
                    |     |     +---- Attribute, on line 4, connection.cursor
                    |     |           |
                    |     |           +---- Name, on line 4, connection
                    |     |
                    |     +---- Name, on line 4, cursor
                    |
                    +---- Expr, on line 5
                          |
                          +---- Call, on line 5
                          |     |
                          |     |---- Attribute, on line 5, cursor.execute
                          |     |
                          |     +---- Name, on line 5, cursor
                          |
                          +---- BinOp, on line 5
                                |
                                |---- Constant, on line 5, SELECT * FROM users WHERE username = '%s'
                                |
                                +---- Name, on line 5, username
        ```
    - One type could be a call to a method. We can see the node `Call, on line 5`, which is a call to a method with its qualifier (`cursor.execute`) and arguments (here the argument list is empty) represented as child nodes
- With the AST of the source code, we could query for all the nodes representing method calls to `execute` from the `django.db` library. That would return only method calls to `execute`, not any other types that we might not be interested in. Then, we could query for all method calls to `execute` that do not take a string literal as an argument. That would exclude the calls from the results that use plain strings - so the ones that do not use any potentially unsafe data
- To make our analysis even more accurate, we can use another representation of source code called *Control Flow Graph (CFG)*. A control flow graph describes the flow of control, that is the order in which the AST nodes are evaluated in all possible runs of a program, where each node corresponds to a primitive statement in the program. These primitive statements include assignments and conditions. Edges going out from a node denote a possible successor of that statement in the same run of the program. With CFG, we can track how the code flows throughout the program and perform further analysis
### Data flow analysis and taint tracking

### Static analysis
- A process that allows us to analyze an application's code for potential errors without executing the code itself
