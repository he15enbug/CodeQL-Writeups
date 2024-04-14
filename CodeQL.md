# Background
- [CodeQL zero to hero part 1: the fundamentals of static analysis for vulnerability research](https://github.blog/2023-03-31-codeql-zero-to-hero-part-1-the-fundamentals-of-static-analysis-for-vulnerability-research/)
## Vulnerability detection - sources and sinks
- There are many types of vulnerabilities - some are easier to find with static analysis, some with other means, and some can only be find through manual analysis. One of the types of vulnerabilities that static analysis can find are injection vulnerabilities
- The main cause of injection vulnerabilities is untrusted, user-controlled input being used in sensitive or dangerous functions of the program. We use terms such as *data flow*, *sources*, and *sinks* to represent these in static analysis
- *Sources*: the origin of data, where user input comes from, generally the entry points to an application, e.g., HTTP GET request parameters
- *Sinks*: dangerous functions that should not be called with unsanitized untrusted data, e.g., `MySQLCursor.execute()` from the MySQLdb library in Python or the built-in function `eval()` in Python. Sinks are potentially dangerous, but they are not always immediately exploitable. Many sinks have ways of using them safely
- For a vulnerability to be present, the unsafe, user-controlled input has to be used without proper sanitization or validation in a dangerous function, i.e., there has to be a code path between the source and the sink, in which case we say that data flows from a source to a sink
## Finding sources and sinks
- We could do so manually by using the `*nix` utility `grep`, and start by searching for sources such as GET requests, e.g., look for all places in the codebase, in which GET requests are accessed
    - Problems
        1. `grep` will also match some innocuous function names and comments (False Positives)
        2. we can only search for one type of sources and review it one at a time
    - The earliest static analysis tools for security review were designed to solve these problems
## Early static analysis tools - lexical pattern matching
- Many of the steps taken by a static analysis tools are similar to the ones of a compiler or interpreter. Compilers and interpreters already perform a form of static analysis: type checking. We could adapt technologies in compilers to use in static analysis for security review
- The first problem with `grep` was that it returns results from comments and function names. We can easily filter out these results with *lexical analysis* - a well-known compiler technology. Lexical analysis reads the source code and transforms it from a stream of characters into a stream of tokens, ignoring any characters that do not contribute to the semantics of the code. Tokens consists of characters, for example, a comma, literals; for example, strings and integers or the reserved words in the language; for example, `with`, `def` in Python
- Another important feature that was introduced in static analysis tools at that time was a knowledge base containing information about dangerous sinks, and matched the sink name from the tokens. Upon match, the information about the dangerous sink and why it might be dangerous to use was displayed
- We solved the first problem. Now, we can detect sources and sinks automatically without too many false positives. The second problem still stands though - tools report on dangerous sinks, which might not have been used with untrusted data or in a way causing a vulnerability (still many false positives)
- An obvious solution is to check whether there is a connection between a source and sink
## Syntactic pattern matching, abstract syntax tree, and control flow graph
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
## Data flow analysis and taint tracking
- We can utilize a control flow graph to check if there is a connection between a given source and a sink - a data flow. This technique is called *Data Flow Analysis*. Data flow analysis leverages the CFG and other representations such as the *Call Graph* and the *Static Single Assignment (SSA)* form to emulate data propagating throughout the code.
- The problem with data flow analysis is that it only tracks value-preserving data, that is data that does not change. As an example, if a string is concatenated with another string, then a new string with a different value is created and data flow analysis would not track it
- *Taint Tracking* is used to solve this problem. It works similarly to data flow analysis, but with slightly different rules. Taint tracking marks certain inputs (sources) as `tainted` (i.e., unsafe, user-controlled), which allows a static analysis tool to check if a tainted input propagates all the way to a defined spot in our application, such as the argument to a dangerous function
- What if a source is sanitized (e.g., `MySQLdb.escape_string()` to prevent SQL injection)? If one of the nodes in the data flow path from the source to the sink uses sanitization, the tool will stop the flow from propagating and thus not provide a result on a given data flow which uses sanitization. It might happen though that the codebase uses **custom, uncommon** sanitization methods, that a static analyzer does not support, in which case the tool will still report on the said issue. Static analysis tools normally offer a way to define what constitutes a sanitizer or a taint step (an edge between two data flow nodes) to allow users to customize the analysis to their own code and libraries
## Other internal representations
- *Call Graph*, representation of potential control flow between functions or methods
    - Nodes: functions
    - Directed edges: the potential for one function to invoke another
- *Single Static-Assginment (SSA)*, in which CFG is modified so that every single variable is assigned exactly once. The SSA form considerably improves the precision of various data flow analysis methods. Static analysis tools often use several representations to capture advantages of using each of them and deliver more precise results
## Conclusion
- Many static analysis tools' methods stem from compiler technology
- The anatomy of most static code analysis tools can be summarized into three components:
    1. The parser: parse the code into an internal representation
    2. The internal representation
    3. The analysis of the representation
        - Sound or unsound
        - Flow sensitive or flow insensitive
        - Safe or unsafe
        - For more about the analyses, read ["Source Code Analysis: A Road Map" by David Binkley](https://ieeexplore.ieee.org/document/4221615?arnumber=4221615)
# CodeQL
- [CodeQL](https://codeql.github.com/) is a static anlysis tool that can be used to automatically scan our applications for vulnerabilities and to assist with a manual code review. It uses data flow analysis and taint analysis methods
- [Documentation](https://codeql.github.com/docs/)
- [CodeQL zero to hero part 2: getting started with CodeQL](https://github.blog/2023-06-15-codeql-zero-to-hero-part-2-getting-started-with-codeql/)
- Supported languages: C/C++, C#, Go, Java, Kotlin, JavaScript, Python, Ruby, TypeScript, and Swift
## Common uses of CodeQL for security research and application security
- Uses for CodeQL
    1. Automated scanning of source code for [hundreds of vulnerability types](https://codeql.github.com/codeql-query-help/full-cwe/)
    2. Variant analysis. If a vulnerability has been found in my code base, for example, SQL injection, I can use CodeQL to see if there are other cases of the same vulnerability in a different part of the codebase.
    3. Assistance during manual code review. We can “ask CodeQL questions” about the analyzed codebase, for example:
        1. What is my attack surface? Where should I start my audit?
        2. What are the sources (unsafe user-supplied input) and sinks (dangerous functions) in my code base?
        3. Do the sources end up in any dangerous or untrusted functionality?
## Introduction
- The **key idea** behind CodeQL is that it analyzes code as data by creating a database of facts about the program and then using a special query language, called QL, to query the database for vulnerable patterns. QL is an expressive, declarative, logical query language for identifying patterns in the database, that is vulnerabilities, for example, SQL injection
## Code scanning with CodeQL
- Enabling the [code scanning with CodeQL GitHub Action](https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning)
## CodeQL databases
- A CodeQL database is created automatically when we enable the code scanning with CodeQL action on a repository. But what if we would like to modify a query or query for specific artifacts ourselves?
- At high level, the process works as follows: for each language CodeQL extracts the source code, converting it to understand it either by parsing the code directly or by instrumenting executions of a compiler that already exists for that language within a running build. The database itself is a relational representation of the code base, which contains information about the different source code elements, such as classes and functions, and puts each of those into a separate table of data. Each language has its own database schema, but generally there is a table for classes, a table for functions and so on, and relationships between these tables. CodeQL standard libraries for each language provide wrappers and layers around that database schema. We use the QL query language to query these tables and relationships
- CodeQL databases already exist for many of the most popular open source projects on GitHub, they are available to download by using the CodeQL extension in VS Code or GitHub via the [GitHub API](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/preparing-your-code-for-codeql-analysis#downloading-databases-from-githubcom). But if it happens that a CodeQL database is not available for an open source repository, requesting it will trigger an attempt for database creation
- We can also create a CodeQL database ourselves locally, using the [CodeQL command line tool](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/about-the-codeql-cli). The easiest way to install the CodeQL CLI locally is as an extension to the [`gh`](https://github.com/cli/cli) CLI
### Create CodeQL database using CodeQL CLI locally
#### Install CodeQL CLI
1. Install `gh`: `winget install --id GitHub.cli` (on Windows). The Windows installer modifies the `PATH`, when using Windows terminal, we will need to open a new window for the changes to take effect. [More instructions](https://github.com/cli/cli#installation)
2. The first time we use it, we need to login `gh auth login`
3. Install the CodeQL extension
    ```
    gh extensions install github/gh-codeql
    gh codeql install-stub
    ```
#### Create a CodeQL database
1. Clone the example repo: `git clone https://github.com/GitHubSecurityLab/codeql-zero-to-hero.git`
2. Move to the cloned directory: `cd codeql-zero-to-hero/`
3. Create a CodeQL database: `gh codeql database create example-codeql-db --language=python`, and wait
4. Deactivate the virtual environment: `deactivate`
5. Go to the VS Code CodeQL extension, click on the "Choose Database from folder" icon and select the "example-codeql-db" that we created in previous step


## QL query language—writing your own CodeQL query
- Query the CodeQL database and write our own CodeQL queries using QL
- We can query the CodeQL DB for syntactic elements, such as AST nodes (e.g., a function call or a function definition), and for semantic elements, such as the nodes in the data flow graph of a program. The data flow graph is one of the structures that CodeQL creates on top of the AST and contains information about the data flow within a program. With data flow graph, we can query if there is a connection between, e.g., a source and a SQL injection sink
- Example questions:
    - Show me all function calls
    - Show me all function calls called `eval`
    - Show me all function definitions for functions called `eval`
    - Show me all method calls to methods called `execute`defined within the `django.db` library that do not take a string literal as input
### Basic CodeQL query
- The basic syntax and structure of a CodeQL query resembles SQL and consists of three statements: `from`, `where`, and `select`
- `from` defines the types and variables that are going to be queried
- `where` defines conditions on these variables in the form of a logical formula. Can be omitted if there is no condition
- `select` defines the output of the query
- Example: ask CodeQL for all function calls in a Python codebase
    ```
    import python

    from Call c
    where c.getLocation().getFile().getRelativePath().regexpMatch("2/challenge-1/.*")
    select c, "This is a function call"
    ```
### Refining a QL query
- Look for all function calls to `eval`
    ```
    1. import python
    2.
    3. from Call c, Name name
    4. where name.getId() = "eval" and
    5. c.getFunc() = name and
    6. c.getLocation().getFile().getRelativePath().regexpMatch("2/challenge-1/.*")
    7. select c
    ```
- QL is a logical language: it allows for specifying logic conditions for patterns in code using common logical operators `and`, `or`, `not`. It is also a declarative language: order for specifying conditions does not matter
- The `Name` type refers to variables and it contains their name. In some languages, such as Python, every named entity is a variable. In the `eval()` example, `eval` is a variable read, and `()` is the call operator. In this context we are calling whatever function is held by the `eval` variable. We can think of `Name` as a variable read expression
- `c.getFunc() = name`: call the `getFunc()` operation on `c` to get the callable of the call, so the function itself. Then, we restrict it with the value of the `name` variable (which we restricted to `eval` using `name.getId() = "eval"`)
- These "operations" we called on the variables are called *predicates* (to be more precise - built-in predicates) and are similar to functions

## Challenges
### Challenge-2
- [Instructions](https://github.com/GitHubSecurityLab/codeql-zero-to-hero/blob/main/2/challenge-2/instructions.md)
- We use Option A: GitHub Codespace
- Open the Command Palette with `Ctrl+Shift+P` and type `CodeQL: Create Query`, select language (`Python`) and repository (`GitHubSecurityLab/codeql-zero-to-hero`)
- We will be able to write CodeQL for Python queries inside the folder `codeql-custom-queries-python` that was generated
