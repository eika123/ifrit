---
name: go-modern-guardrails
description: Combines core idiomatic Go standards with strict rules for repairing broken code/syntax errors caused by failed refactoring.
triggers:
  - "go build error"
  - "compile error go"
  - "type mismatch"
  - "too many arguments"
  - "undefined"
  - "broken interface"
  - "fix go build"
---

# Go Modern Guardrails & Refactor Repair

You are assisting in restoring and expanding a previously broken Go codebase. A recent refactoring introduced syntax and type errors. The examples
 `_examples/messagesExample.go` and `streamingExample.go` have not been tested after our fixes, but `gossipContentExample.go` runs cleanly.
We must keep a clean `go build` state using modern, idiomatic, and type-safe Go practices.

## 1. Absolute Go Behavioral Bans
Do NOT use these legacy "quick-fixes" or anti-patterns to bypass compiler errors:
* **No Blind Blank Identifiers:** Never discard errors using `_` (e.g., `res, _ := Call()`) to silence a compilation error. Errors must be checked explicitly.
* **No Naked Panics:** Do not inject `panic()` or improper `recover()` blocks as a substitute for structured error handling. Return `error` as the last value. Panicking functions must explicitly state this in Doc comments that state the conditions under whitch the function panics.
* **No Escape to `any` or `interface{}`:** Do not change function parameters, struct fields, or return types to `any` or `interface{}` just to bypass a type mismatch.
* **No Type Assertions Without Verification:** Never use unchecked type assertions (e.g., `x.(ConcreteType)`). Always use the comma-ok idiom (`v, ok := x.(ConcreteType)`) and handle the `!ok` case.
* **No Dead Code Accommodations:** Do not comment out broken function calls or blocks of logic just to make the file compile. Fix the underlying signature mismatch.
* **No `init()` Side Effects:** Do not fix state or dependency issues by introducing magic global variables or heavy logic inside `init()` functions.

## 2. Idiomatic Go & Refactoring Repair Strategies
When resolving compiler messages (such as `undefined`, `cannot use`, or `wrong number of return values`), enforce these standards:
* **Trace the Source of Truth:** Before fixing a call site, inspect the actual definition of the struct, interface, or function in its declaring package to understand the refactoring intent.
* **Modern Error Wrapping:** Always wrap errors to preserve context using `fmt.Errorf("context: %w", err)` instead of returning generic text errors.
* **Immediate Defer for Resources:** If a fix requires opening a resource (files, rows, channels), enforce immediate leak prevention using `defer resource.Close()` right after the error check.
* **Keep Changes Localized but Complete:** Ensure that fixing a signature in one package completes the entire chain of dependency for that specific type change across the workspace.

## 3. Do not mutate git history
It is important that the user keeps control over what is commited to the git history. Do not mutate it.

## 4. Software development practices
When implementing code, interpret the prompt minimally so that git history can be kept clean. Make minimal edits that satisfy the requirement, following the
verification protocol in point ## 5. below.

You write readable code with descriptive variable names and informative comments that explain why things are done.
If necessary, explain what is done. The code should always be self-explaining for how things are done.

After implementing a piece of code, provide a commit message that details what was done in typically 10-20 lines, prefering short messages with good overall information.
The commit message must always provide two items:
* What was your contributioin (the agent).
* What was the contribution of the user.


## 5. Verification Protocol
Before declaring a compiler error resolved, the workspace must be validated using standard Go tooling:
1. `go fmt ./...` (To enforce strict style consistency)
2. `go vet ./...` (To catch structural, shadow variables, and copy locks)
3. `go build ./...` (To ensure the workspace compiles seamlessly)
4. `go test ./...` (Check unit test state vs. what was before fixes)
5. `go test -race ./...` (Check for race conditions)

