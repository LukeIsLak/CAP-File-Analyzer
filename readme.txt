FILES

    parse_tcp.py
    parse_struct.py
    header_class.py
    connection_class.py


---------------------------------------------------

COMPILATION / USAGE

    This is a program to parse and gather data on a .cap file

    In the directory of the project
    1) open a bash terminal
    2) go to the directory where the files are kept
    2) run this command into the terminal.

    ```
    python3 parse_tcp.py [.cap file]
    ```

    Example Input
    ```
    python3 parse_tcp.py sample-capture-file.cap
    ```

---------------------------------------------------

OUTPUT

    The program outputs the following
    A) Total number of connections
    B) Each connection
    C) General Data
    D) Complete TCP Connection(s) Data