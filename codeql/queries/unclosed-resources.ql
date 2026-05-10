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
 * Checks if there's a defer statement with Close() in the function.
 * This is a conservative check - if there's any defer Close() in the function,
 * we assume the resource might be cleaned up (to avoid false positives).
 */
predicate hasDeferWithClose(FuncDef f) {
  exists(DeferStmt defer, SelectorExpr sel |
    defer.getEnclosingFunction() = f and
    sel.getParent+() = defer and
    sel.getSelector().getName() = "Close"
  )
}

/**
 * Checks if there's a testing.TB.Cleanup() call with Close() in the function.
 * This handles patterns like: t.Cleanup(func() { _ = r.Close() })
 */
predicate hasTestingCleanupWithClose(FuncDef f) {
  exists(DataFlow::CallNode cleanup, FuncLit cleanupFunc, SelectorExpr sel |
    cleanup.getTarget().getName() = "Cleanup" and
    cleanup.asExpr().getEnclosingFunction() = f and
    cleanupFunc = cleanup.getArgument(0).asExpr() and
    sel.getParent+() = cleanupFunc and
    sel.getSelector().getName() = "Close"
  )
}

/**
 * Checks if the resource is cleaned up.
 */
predicate hasCleanup(DataFlow::CallNode create, DataFlow::Node resource, FuncDef f) {
  hasDirectClose(resource, f)
  or
  hasDeferWithClose(f)
  or
  hasTestingCleanupWithClose(f)
  or
  hasCloseOnSameVariable(create, f)
}

from DataFlow::CallNode create, DataFlow::Node resource, FuncDef enclosingFunc
where
  (create instanceof RepositoryCreation or create instanceof StorageCreation) and
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
  not create.getTarget().hasQualifiedName("github.com/go-git/go-git/v6/storage/memory", "NewStorage")
select create.asExpr(),
  "Resource created but may not be closed. " +
  "Always call defer func() { _ = r.Close() }() after creating Repository or Storage instances."
