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
 * A type that represents either `*Repository` or a Storage type that needs closing.
 */
class ResourceType extends Type {
  ResourceType() {
    // Repository type
    this.(PointerType).getBaseType().hasQualifiedName("github.com/go-git/go-git/v6", "Repository")
    or
    // filesystem.Storage
    this.(PointerType).getBaseType().hasQualifiedName("github.com/go-git/go-git/v6/storage/filesystem", "Storage")
    or
    // transactional.Storage
    this.(PointerType).getBaseType().hasQualifiedName("github.com/go-git/go-git/v6/storage/transactional", "Storage")
  }
}

/**
 * A function call that creates a resource (Repository or Storage).
 */
class ResourceCreation extends CallExpr {
  ResourceCreation() {
    exists(Function f | f = this.getTarget() |
      // Repository creation functions
      f.hasQualifiedName("github.com/go-git/go-git/v6", ["PlainOpen", "PlainOpenWithOptions", "PlainClone", "PlainCloneContext", "PlainInit", "Init", "Clone", "CloneContext", "Open"])
      or
      // Storage creation functions
      f.hasQualifiedName("github.com/go-git/go-git/v6/storage/filesystem", ["NewStorage", "NewStorageWithOptions"])
      or
      f.hasQualifiedName("github.com/go-git/go-git/v6/storage/transactional", "NewStorage")
      or
      // Submodule.Repository() method
      f.hasQualifiedName("github.com/go-git/go-git/v6", "Submodule", "Repository")
      or
      // Worktree.Repository() method
      f.hasQualifiedName("github.com/go-git/go-git/v6", "Worktree", "Repository")
      or
      // Repository.Worktree() method returns a Worktree with repository field
      f.hasQualifiedName("github.com/go-git/go-git/v6", "Repository", "Worktree")
    )
  }
}

/**
 * A call to Close() method on a resource.
 */
class CloseCall extends MethodCall {
  CloseCall() {
    this.getTarget().getName() = "Close" and
    this.getReceiver().getType() instanceof ResourceType
  }
}

/**
 * Checks if a variable has a Close() call (direct or in defer) in the same function.
 */
predicate hasCloseCall(SsaVariable v) {
  exists(CloseCall close |
    close.getReceiver() = v.getAUse()
  )
  or
  // Check for defer Close() patterns
  exists(DeferStmt defer, CloseCall close |
    defer.getCall() = close and
    close.getReceiver() = v.getAUse()
  )
  or
  // Check for defer func() { _ = x.Close() }() patterns
  exists(DeferStmt defer, FuncLit fn, AssignStmt assign, CloseCall close |
    defer.getCall().(CallExpr).getCalleeExpr() = fn and
    fn.getBody().getAStmt() = assign and
    assign.getRhs(0) = close and
    close.getReceiver() = v.getAUse()
  )
}

from ResourceCreation create, SsaVariable v
where
  // The resource is assigned to a variable
  v.getDefinition().(SsaExplicitDefinition).getInstruction().getNode() = create and
  // The variable is not closed
  not hasCloseCall(v) and
  // The variable is not assigned to a field (which might be closed elsewhere)
  not exists(Field f | v.getAUse() = f.getAWrite().getRhs()) and
  // The variable is not returned (caller's responsibility)
  not exists(ReturnStmt ret | v.getAUse() = ret.getExpr())
select create, "This resource is created but never closed, which may cause file handle leaks."
