/**
 * @name Unclosed Repository or Storage
 * @description Detects Repository or Storage instances that are created but never closed,
 *              which can lead to file handle leaks on Windows.
 * @kind problem
 * @problem.severity warning
 * @id go-git/unclosed-resources
 * @tags reliability
 *       resource-management
 */

import go

/**
 * A function that creates a Repository
 */
class RepositoryCreation extends DataFlow::CallNode {
  RepositoryCreation() {
    this.getTarget().hasQualifiedName("github.com/go-git/go-git/v6", [
      "PlainOpen", "PlainOpenWithOptions", "PlainClone", "PlainCloneContext",
      "PlainInit", "Init", "Clone", "CloneContext", "Open"
    ])
  }
}

/**
 * A function that creates a Storage
 */
class StorageCreation extends DataFlow::CallNode {
  StorageCreation() {
    this.getTarget().hasQualifiedName("github.com/go-git/go-git/v6/storage/filesystem", [
      "NewStorage", "NewStorageWithOptions"
    ])
    or
    this.getTarget().hasQualifiedName("github.com/go-git/go-git/v6/storage/transactional", "NewStorage")
  }
}

/**
 * A call to a user-defined factory function that returns a Repository or Storage.
 */
class FactoryCall extends DataFlow::CallNode {
  FactoryCall() {
    exists(Type resultType |
      resultType = this.getTarget().getResultType(0) |
      (
        resultType.getUnderlyingType().(PointerType).getBaseType().hasQualifiedName("github.com/go-git/go-git/v6", "Repository")
        or
        resultType.getUnderlyingType().(PointerType).getBaseType().hasQualifiedName("github.com/go-git/go-git/v6/storage/filesystem", "Storage")
        or
        resultType.getUnderlyingType().(PointerType).getBaseType().hasQualifiedName("github.com/go-git/go-git/v6/storage/transactional", "Storage")
        or
        resultType.getName() = ["Storer", "EncodedObjectStorer"]
      ) and
      // Exclude the direct creation functions (already covered by RepositoryCreation/StorageCreation)
      not this instanceof RepositoryCreation and
      not this instanceof StorageCreation
    )
  }
}

/**
 * A function that returns a Repository or Storage (factory function).
 * Resources returned by factory functions are the caller's responsibility to close.
 */
predicate isFactoryFunction(FuncDef f) {
  exists(Type resultType |
    resultType = f.getType().getResultType(0) |
    resultType.getUnderlyingType().(PointerType).getBaseType().hasQualifiedName("github.com/go-git/go-git/v6", "Repository")
    or
    resultType.getUnderlyingType().(PointerType).getBaseType().hasQualifiedName("github.com/go-git/go-git/v6/storage/filesystem", "Storage")
    or
    resultType.getUnderlyingType().(PointerType).getBaseType().hasQualifiedName("github.com/go-git/go-git/v6/storage/transactional", "Storage")
    or
    // Storage-related interfaces
    resultType.getName() = ["Storer", "EncodedObjectStorer"]
  )
}

/**
 * Checks if a factory call returns a resource from a function that only creates memory storage.
 * This analyzes what storage types are created inside the factory function.
 */
predicate factoryCallCreatesOnlyMemoryStorage(FactoryCall call) {
  exists(FuncDef factory |
    // Match function by target binding (not just name)
    factory = call.getTarget().getFuncDecl() and
    // Factory creates memory storage
    exists(DataFlow::CallNode memCreate |
      memCreate.asExpr().getEnclosingFunction() = factory and
      memCreate.getTarget().hasQualifiedName("github.com/go-git/go-git/v6/storage/memory", "NewStorage")
    ) and
    // And doesn't create any filesystem or transactional storage
    not exists(DataFlow::CallNode fsCreate |
      fsCreate.asExpr().getEnclosingFunction() = factory and
      (
        fsCreate.getTarget().hasQualifiedName("github.com/go-git/go-git/v6/storage/filesystem", _) or
        fsCreate.getTarget().hasQualifiedName("github.com/go-git/go-git/v6/storage/transactional", _)
      )
    ) and
    // And doesn't open repositories (which use filesystem storage)
    not exists(DataFlow::CallNode repoCreate |
      repoCreate.asExpr().getEnclosingFunction() = factory and
      repoCreate instanceof RepositoryCreation
    )
  )
}

/**
 * Checks if a factory call returns a pre-existing resource rather than creating a new one.
 * These are "getter" factories that return resources from maps, fields, or parameters.
 */
predicate factoryCallReturnsExistingResource(FactoryCall call) {
  exists(FuncDef factory |
    // Match function by target binding
    factory = call.getTarget().getFuncDecl() and
    // Factory doesn't create any new storage or repository
    not exists(DataFlow::CallNode create |
      create.asExpr().getEnclosingFunction() = factory and
      (
        create instanceof RepositoryCreation or
        create instanceof StorageCreation or
        create.getTarget().hasQualifiedName("github.com/go-git/go-git/v6/storage/memory", "NewStorage")
      )
    )
  )
}

/**
 * Checks if a factory call creates resources and also registers cleanup for them.
 * These are cache-or-create factories that handle their own cleanup.
 */
predicate factoryCallRegistersCleanup(FactoryCall call) {
  exists(FuncDef factory, DataFlow::CallNode create |
    // Match function by target binding
    factory = call.getTarget().getFuncDecl() and
    // Factory creates a repository or storage
    create.asExpr().getEnclosingFunction() = factory and
    (create instanceof RepositoryCreation or create instanceof StorageCreation) and
    // And registers cleanup for it
    hasCleanup(create, create.getResult(0), factory)
  )
}

/**
 * A call to Close() method
 */
class CloseCall extends DataFlow::MethodCallNode {
  CloseCall() {
    this.getTarget().getName() = "Close"
  }
}

/**
 * Checks if there's a direct Close() call using dataflow.
 */
predicate hasDirectClose(DataFlow::Node resource, FuncDef f) {
  exists(CloseCall close |
    DataFlow::localFlow(resource, close.getReceiver()) and
    close.asExpr().getEnclosingFunction() = f
  )
}

/**
 * Checks if there's a Close() call on the same variable name.
 * This handles cases where dataflow doesn't track through embedded fields.
 */
predicate hasCloseOnSameVariable(DataFlow::CallNode create, FuncDef f) {
  exists(CallExpr closeCall, SelectorExpr sel, Ident closeVar, Ident createVar, string varName |
    // The Close() call
    closeCall.getEnclosingFunction() = f and
    sel.getParent() = closeCall and
    sel.getSelector().getName() = "Close" and
    closeVar = sel.getBase() and
    closeVar.getName() = varName and
    // The creation assignment (handles both := and =)
    (
      create.asExpr().getParent().(DefineStmt).getLhs() = createVar or
      create.asExpr().getParent().(AssignStmt).getLhs() = createVar
    ) and
    createVar.getName() = varName
  )
}

/**
 * Checks if there's a defer statement that closes a specific resource.
 * This matches the variable name from the creation to the defer Close().
 * Handles both simple assignments and tuple assignments.
 */
predicate hasDeferCloseOnVariable(DataFlow::CallNode create, FuncDef f) {
  exists(DeferStmt defer, SelectorExpr sel, Ident deferVar, Ident createVar, string varName |
    // The defer Close() call
    defer.getEnclosingFunction() = f and
    sel.getParent+() = defer.getCall() and
    sel.getSelector().getName() = "Close" and
    deferVar = sel.getBase() and
    deferVar.getName() = varName and
    // The creation assignment
    (
      // Simple assignment: x := Create()
      (
        create.asExpr().getParent().(DefineStmt).getLhs() = createVar or
        create.asExpr().getParent().(AssignStmt).getLhs() = createVar
      ) or
      // Tuple assignment: x, err := Create() - check first element (index 0)
      (
        create.asExpr().getParent().(DefineStmt).getLhs(0) = createVar or
        create.asExpr().getParent().(AssignStmt).getLhs(0) = createVar
      )
    ) and
    createVar.getName() = varName
  )
}

/**
 * Checks if there's a defer statement with a type assertion and Close() call.
 * This handles patterns like:
 *   defer func() { if closer, ok := st.(io.Closer); ok { closer.Close() } }()
 * Works with any closer interface (io.Closer, custom interfaces, dot imports, aliases).
 */
predicate hasDeferWithTypeAssertion(DataFlow::CallNode create, FuncDef f) {
  exists(DeferStmt defer, TypeAssertExpr typeAssert, Ident assertedVar, Ident createVar,
         SelectorExpr closeCall, Ident closedVar, string varName, string closerName |
    // The defer statement is in the same function
    defer.getEnclosingFunction() = f and
    // There's a type assertion inside the defer
    typeAssert.getParent+() = defer.getCall() and
    // The type assertion is on our variable
    assertedVar = typeAssert.getExpr() and
    assertedVar.getName() = varName and
    // The type assertion result is assigned to a variable (e.g., closer, ok := ...)
    typeAssert.getParent().(DefineStmt).getLhs(0).(Ident).getName() = closerName and
    // There's a Close() call on the asserted variable within the defer
    closeCall.getParent+() = defer.getCall() and
    closeCall.getSelector().getName() = "Close" and
    closedVar = closeCall.getBase() and
    closedVar.getName() = closerName and
    // Match to the creation variable
    (
      // Simple assignment
      (
        create.asExpr().getParent().(DefineStmt).getLhs() = createVar or
        create.asExpr().getParent().(AssignStmt).getLhs() = createVar
      ) or
      // Tuple assignment - check first element (index 0)
      (
        create.asExpr().getParent().(DefineStmt).getLhs(0) = createVar or
        create.asExpr().getParent().(AssignStmt).getLhs(0) = createVar
      )
    ) and
    createVar.getName() = varName
  )
}

/**
 * Checks if there's a testing.TB.Cleanup() call that closes the specific resource.
 * This handles patterns like:
 *   t.Cleanup(func() { _ = r.Close() })
 * Or with type assertion:
 *   t.Cleanup(func() { if c, ok := r.(io.Closer); ok { c.Close() } })
 */
predicate hasTestingCleanupWithClose(DataFlow::CallNode create, FuncDef f) {
  // Direct cleanup where creation variable name matches cleanup variable name
  exists(DataFlow::CallNode cleanup, FuncLit cleanupFunc, Ident createVar, string varName |
    // The cleanup call
    cleanup.getTarget().getName() = "Cleanup" and
    cleanup.asExpr().getEnclosingFunction() = f and
    cleanupFunc = cleanup.getArgument(0).asExpr() and
    // Match to the creation variable
    (
      create.asExpr().getParent().(DefineStmt).getLhs() = createVar or
      create.asExpr().getParent().(AssignStmt).getLhs() = createVar or
      create.asExpr().getParent().(DefineStmt).getLhs(0) = createVar or
      create.asExpr().getParent().(AssignStmt).getLhs(0) = createVar
    ) and
    createVar.getName() = varName and
    // The cleanup function closes the resource (either directly or via type assertion)
    (
      // Direct Close: r.Close()
      exists(SelectorExpr sel, Ident cleanupVar |
        sel.getParent+() = cleanupFunc and
        sel.getSelector().getName() = "Close" and
        cleanupVar = sel.getBase() and
        cleanupVar.getName() = varName
      )
      or
      // Type assertion Close: if c, ok := r.(io.Closer); ok { c.Close() }
      exists(TypeAssertExpr typeAssert, Ident assertedVar, SelectorExpr closeCall, Ident closedVar, string closerName |
        typeAssert.getParent+() = cleanupFunc and
        assertedVar = typeAssert.getExpr() and
        assertedVar.getName() = varName and
        typeAssert.getParent().(DefineStmt).getLhs(0).(Ident).getName() = closerName and
        closeCall.getParent+() = cleanupFunc and
        closeCall.getSelector().getName() = "Close" and
        closedVar = closeCall.getBase() and
        closedVar.getName() = closerName
      )
    )
  )
  or
  // Dataflow-based cleanup detection: check if resource flows to cleanup Close() call
  exists(DataFlow::CallNode cleanup, FuncLit cleanupFunc, CloseCall closeCall |
    cleanup.getTarget().getName() = "Cleanup" and
    cleanup.asExpr().getEnclosingFunction() = f and
    cleanupFunc = cleanup.getArgument(0).asExpr() and
    closeCall.asExpr().getEnclosingFunction+() = cleanupFunc and
    DataFlow::localFlow(create.getResult(0), closeCall.getReceiver())
  )
  or
  // Pattern: s.Field = Create(); r := s.Field; t.Cleanup(func() { r.Close() })
  exists(DataFlow::CallNode cleanup, FuncLit cleanupFunc, SelectorExpr sel, Ident cleanupVar,
         string cleanupVarName, SelectorExpr fieldLhs, string fieldName, DefineStmt copyStmt,
         Ident copyLhs, SelectorExpr copyRhs |
    // The cleanup call
    cleanup.getTarget().getName() = "Cleanup" and
    cleanup.asExpr().getEnclosingFunction() = f and
    cleanupFunc = cleanup.getArgument(0).asExpr() and
    // The cleanup function closes a variable
    sel.getParent+() = cleanupFunc and
    sel.getSelector().getName() = "Close" and
    cleanupVar = sel.getBase() and
    cleanupVar.getName() = cleanupVarName and
    // The variable was assigned from a struct field
    copyStmt.getEnclosingFunction() = f and
    copyStmt.getLhs() = copyLhs and
    copyLhs.getName() = cleanupVarName and
    copyStmt.getRhs() = copyRhs and
    copyRhs.getSelector().getName() = fieldName and
    // The creation was assigned to that struct field
    fieldLhs = create.asExpr().getParent().(AssignStmt).getLhs() and
    fieldLhs.getSelector().getName() = fieldName
  )
}

/**
 * Checks if the resource is closed in a function literal that is returned.
 * This handles patterns like:
 *   st := loader.Load(url)
 *   closeAll := func() error { st.Close() }
 *   return ..., closeAll
 * Or with type assertion:
 *   closeAll := func() error { if c, ok := st.(io.Closer); ok { c.Close() } }
 * Where the caller is responsible for invoking the cleanup callback.
 */
predicate isClosedViaReturnedCallback(DataFlow::CallNode create, FuncDef f) {
  exists(FuncLit callback, Ident createVar, string varName, ReturnStmt ret |
    // The resource is assigned to a variable
    (
      create.asExpr().getParent().(DefineStmt).getLhs() = createVar or
      create.asExpr().getParent().(AssignStmt).getLhs() = createVar or
      create.asExpr().getParent().(DefineStmt).getLhs(0) = createVar or
      create.asExpr().getParent().(AssignStmt).getLhs(0) = createVar
    ) and
    createVar.getName() = varName and
    // A function literal is defined in the same function
    callback.getEnclosingFunction() = f and
    // The callback closes the resource (either directly or via type assertion)
    (
      // Direct Close: st.Close()
      exists(SelectorExpr closeCall, Ident closeVar |
        closeCall.getParent+() = callback and
        closeCall.getSelector().getName() = "Close" and
        closeVar = closeCall.getBase() and
        closeVar.getName() = varName
      )
      or
      // Type assertion Close: if c, ok := st.(SomeCloser); ok { c.Close() }
      exists(TypeAssertExpr typeAssert, Ident assertedVar, SelectorExpr closeCall, Ident closedVar, string closerName |
        typeAssert.getParent+() = callback and
        // Don't check type name - works with any closer interface
        assertedVar = typeAssert.getExpr() and
        assertedVar.getName() = varName and
        typeAssert.getParent().(DefineStmt).getLhs(0).(Ident).getName() = closerName and
        closeCall.getParent+() = callback and
        closeCall.getSelector().getName() = "Close" and
        closedVar = closeCall.getBase() and
        closedVar.getName() = closerName
      )
    ) and
    // The function literal (or a variable containing it) is returned
    ret.getEnclosingFunction() = f and
    (
      // Direct return: return ..., funcLit
      callback.getParent+() = ret
      or
      // Indirect return via variable: x := funcLit; return ..., x
      exists(Ident callbackVar, Ident retVar, string cbName |
        (
          callback.getParent().(DefineStmt).getLhs() = callbackVar or
          callback.getParent().(AssignStmt).getLhs() = callbackVar
        ) and
        callbackVar.getName() = cbName and
        retVar.getParent() = ret and
        retVar.getName() = cbName
      )
    )
  )
}

/**
 * Checks if a creation is followed by an error assertion indicating an error path test.
 * This handles patterns like:
 *   r, err := Open(memory.NewStorage(), nil)
 *   require.Error(t, err) // or s.ErrorIs(err, ...), assert.Error(t, err), etc.
 */
predicate isErrorPathTest(DataFlow::CallNode create, FuncDef f) {
  exists(DataFlow::CallNode errorCheck, string errVarName, Ident errVar, Ident createErrVar |
    // The creation has an error variable in tuple assignment
    (
      create.asExpr().getParent().(DefineStmt).getLhs(1) = createErrVar or
      create.asExpr().getParent().(AssignStmt).getLhs(1) = createErrVar
    ) and
    createErrVar.getName() = errVarName and
    // There's an error checking call in the same function
    errorCheck.asExpr().getEnclosingFunction() = f and
    // The error check is one of the common assertion methods that expect an error
    (
      errorCheck.getTarget().getName() = "Error" or
      errorCheck.getTarget().getName() = "ErrorIs" or
      errorCheck.getTarget().getName() = "ErrorAs" or
      errorCheck.getTarget().getName() = "ErrorContains" or
      errorCheck.getTarget().getName() = "NotNil" or
      errorCheck.getTarget().hasQualifiedName("testing", "Fatal") or
      errorCheck.getTarget().hasQualifiedName("testing", "Fatalf")
    ) and
    // The error check uses the same error variable
    errVar = errorCheck.getAnArgument().asExpr() and
    errVar.getName() = errVarName and
    // The error check happens after the creation (basic ordering heuristic)
    errorCheck.asExpr().getLocation().getStartLine() > create.asExpr().getLocation().getStartLine()
  )
}

/**
 * Checks if the resource is cleaned up.
 * Tries precise tracking first, falls back to conservative heuristics for complex cases.
 */
predicate hasCleanup(DataFlow::CallNode create, DataFlow::Node resource, FuncDef f) {
  // Direct Close() via dataflow
  hasDirectClose(resource, f)
  or
  // defer func() { r.Close() } pattern matched by variable name (precise)
  hasDeferCloseOnVariable(create, f)
  or
  // Close() on same variable (handles embedded fields)
  hasCloseOnSameVariable(create, f)
  or
  // testing.TB.Cleanup() pattern matched by variable name
  hasTestingCleanupWithClose(create, f)
  or
  // defer func() with type assertion to io.Closer
  hasDeferWithTypeAssertion(create, f)
  or
  // Cleanup callback returned to caller
  isClosedViaReturnedCallback(create, f)
}

/**
 * Checks if a resource is passed to a wrapper function that returns a properly-closed resource.
 * This handles patterns like:
 *   temporal := filesystem.NewStorage(...)
 *   st := NewStorage(base, temporal)
 *   defer func() { st.Close() }()
 * Where closing st also closes temporal.
 * Also handles type conversions: temporal := storage.Storer(filesystem.NewStorage(...))
 */
predicate isPassedToClosedWrapper(DataFlow::CallNode create, FuncDef f) {
  // Case 1: Resource assigned to variable, then variable passed to wrapper
  exists(DataFlow::CallNode wrapper, Ident argVar, string varName |
    // The resource is assigned to a variable (may be wrapped in type conversion)
    (
      exists(Ident createVar |
        (
          create.asExpr().getParent().(DefineStmt).getLhs() = createVar or
          create.asExpr().getParent().(AssignStmt).getLhs() = createVar or
          create.asExpr().getParent().(DefineStmt).getLhs(0) = createVar or
          create.asExpr().getParent().(AssignStmt).getLhs(0) = createVar or
          // Handle type conversions: x := Type(create())
          create.asExpr().getParent().getParent().(DefineStmt).getLhs() = createVar or
          create.asExpr().getParent().getParent().(AssignStmt).getLhs() = createVar or
          create.asExpr().getParent().getParent().(DefineStmt).getLhs(0) = createVar or
          create.asExpr().getParent().getParent().(AssignStmt).getLhs(0) = createVar
        ) and
        createVar.getName() = varName
      )
      or
      // Handle var declarations: var x Type = create()
      exists(ValueSpec spec |
        spec = create.asExpr().getParent() and
        varName = spec.getName(0)
      )
      or
      // Handle var declarations with type conversion: var x Type = Type2(create())
      exists(ValueSpec spec |
        spec = create.asExpr().getParent().getParent() and
        varName = spec.getName(0)
      )
    ) and
    // The variable is used as an argument to a wrapper function
    wrapper.asExpr().getEnclosingFunction() = f and
    wrapper.getAnArgument().asExpr() = argVar and
    argVar.getName() = varName and
    // The wrapper returns a Repository or Storage
    (wrapper instanceof RepositoryCreation or
     wrapper instanceof StorageCreation or
     wrapper instanceof FactoryCall) and
    // The wrapper is properly closed
    hasCleanup(wrapper, wrapper.getResult(0), f)
  )
  or
  // Case 2: Resource passed directly as argument to wrapper (inline)
  // Pattern: r := Open(NewStorage(...), ...)
  exists(DataFlow::CallNode wrapper |
    wrapper.asExpr().getEnclosingFunction() = f and
    // The creation is used directly as an argument to the wrapper
    DataFlow::localFlow(create.getResult(0), wrapper.getAnArgument()) and
    // The wrapper returns a Repository or Storage
    (wrapper instanceof RepositoryCreation or
     wrapper instanceof StorageCreation or
     wrapper instanceof FactoryCall) and
    // The wrapper is properly closed
    hasCleanup(wrapper, wrapper.getResult(0), f)
  )
}

from DataFlow::CallNode create, DataFlow::Node resource, FuncDef enclosingFunc
where
  (create instanceof RepositoryCreation or
   create instanceof StorageCreation or
   create instanceof FactoryCall) and
  resource = create.getResult(0) and
  enclosingFunc = create.asExpr().getEnclosingFunction() and
  // Check if there's no cleanup for this resource
  not hasCleanup(create, resource, enclosingFunc) and
  // Exclude factory functions (return Repository/Storage to caller)
  not isFactoryFunction(enclosingFunc) and
  // Exclude resources assigned to struct fields (managed by struct lifecycle)
  not exists(StructLit lit |
    lit.getAnElement().(KeyValueExpr).getValue() = resource.asExpr()
  ) and
  // Exclude direct calls to memory.NewStorage (doesn't need closing)
  not create.getTarget().hasQualifiedName("github.com/go-git/go-git/v6/storage/memory", "NewStorage") and
  // Exclude calls to factory functions that only create memory storage
  not factoryCallCreatesOnlyMemoryStorage(create) and
  // Exclude calls to factory functions that return existing resources (getters, not creators)
  not factoryCallReturnsExistingResource(create) and
  // Exclude calls to factory functions that register their own cleanup (cache-or-create)
  not factoryCallRegistersCleanup(create) and
  // Exclude resources passed to wrappers that are properly closed
  not isPassedToClosedWrapper(create, enclosingFunc) and
  // Exclude error path tests where we expect the call to fail
  not isErrorPathTest(create, enclosingFunc)
select create.asExpr(),
  "Resource created but may not be closed. " +
  "Always call defer func() { _ = r.Close() }() after creating Repository or Storage instances."
