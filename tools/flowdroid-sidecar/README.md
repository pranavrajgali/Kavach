# Kavach FlowDroid sidecar

This source-only adapter pins FlowDroid `2.15.1` through Maven and emits
`flowdroid-sidecar-v1` JSON. Dependency binaries remain in the external Maven
cache and are not committed or vendored.

Build with JDK 17:

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk@17 mvn package
```

The output records complete/partial state, reconstructed Jimple path statements,
source/sink definitions and postdominator-derived direct control predicates.
Manifest-exported and intent-filter context is joined in Python rather than used
as a FlowDroid analysis gate.

