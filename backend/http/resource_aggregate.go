package http

import (
	"context"
	"io"
	"math"
	"os"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
)

// Cooperative limits bound additional traversal, memory and open directory
// handles. A deadline cannot interrupt a filesystem syscall blocked in the kernel.
type resourceAggregateLimits struct {
	entries, depth, pathBytes, batch int
	duration                       time.Duration
	readDir                        func(*os.File, int) ([]os.FileInfo, error)
}

var resourceAggregateCollectedHook func()

type resourceAggregateEntry struct {
	target  authenticatedReadTarget
	size    int64
	indexed bool
}

type resourceAggregateWalk struct {
	ctx       context.Context
	user      *users.User
	root      authenticatedReadTarget
	limits    resourceAggregateLimits
	deadline  time.Time
	entries   []resourceAggregateEntry
	pathBytes int
	failed    bool
	sizes     map[string]int64
	paths     []string
	logical   bool
}

func (walk *resourceAggregateWalk) active() bool {
	return !walk.failed && walk.ctx.Err() == nil && time.Now().Before(walk.deadline)
}

func (walk *resourceAggregateWalk) collect(target authenticatedReadTarget, depth int) (int64, bool, bool) {
	if !walk.active() || depth > walk.limits.depth || len(walk.entries) >= walk.limits.entries ||
		walk.pathBytes+len(target.LogicalPath) > walk.limits.pathBytes || !target.LogicalAccess ||
		target.LogicalPath != target.CanonicalPath {
		return 0, false, false
	}
	size, indexed, supported := target.Index.FreshAggregateEntry(target.LogicalPath, target.Info)
	if !supported {
		return 0, false, false
	}
	walk.pathBytes += len(target.LogicalPath)
	walk.entries = append(walk.entries, resourceAggregateEntry{target: target, size: size, indexed: indexed})
	if !target.Info.IsDir() {
		return size, indexed, true
	}
	if !indexed {
		walk.sizes[target.LogicalPath] = walk.directorySize(0)
		return 0, false, true
	}
	directory, _, openErr := openAuthenticatedReadEntryTarget(target)
	if openErr != nil {
		return 0, false, false
	}
	defer func() {
		if closeErr := directory.Close(); closeErr != nil {
			walk.failed = true
		}
	}()
	var total int64
	hasIndexedChild := false
	for {
		if !walk.active() || len(walk.entries) >= walk.limits.entries {
			return 0, false, false
		}
		batch := walk.limits.batch
		if remaining := walk.limits.entries - len(walk.entries); batch > remaining {
			batch = remaining
		}
		var children []os.FileInfo
		var readErr error
		if walk.limits.readDir != nil {
			children, readErr = walk.limits.readDir(directory, batch)
		} else {
			children, readErr = directory.Readdir(batch)
		}
		if readErr != nil && readErr != io.EOF {
			return 0, false, false
		}
		for _, child := range children {
			if child.Mode()&os.ModeSymlink != 0 || (!child.IsDir() && !child.Mode().IsRegular()) {
				return 0, false, false
			}
			logicalPath := normalizePublicShareIndexPath(utils.JoinPathAsUnix(target.LogicalPath, child.Name()))
			childTarget, resolveErr := resolveAuthenticatedReadIndexTargetWithScope(walk.user, target.Index, walk.root.UserScope, logicalPath)
			if resolveErr != nil || !os.SameFile(child, childTarget.Info) || child.IsDir() != childTarget.Info.IsDir() {
				return 0, false, false
			}
			childSize, counted, complete := walk.collect(childTarget, depth+1)
			if !complete || !walk.active() {
				return 0, false, false
			}
			if counted {
				if childSize < 0 || total > math.MaxInt64-childSize {
					return 0, false, false
				}
				total += childSize
				hasIndexedChild = true
			}
		}
		if readErr == io.EOF {
			break
		}
	}
	if target.Index.Config.ResolvedRules.IgnoreAllZeroSizeFolders && target.LogicalPath != "/" &&
		((target.Index.Config.UseLogicalSize && total == 0) || (!target.Index.Config.UseLogicalSize && !hasIndexedChild)) {
		return 0, false, true
	}
	size = walk.directorySize(total)
	walk.sizes[target.LogicalPath] = size
	return size, true, true
}

func (walk *resourceAggregateWalk) directorySize(size int64) int64 {
	if !walk.root.Index.Config.UseLogicalSize && size < 4096 {
		return 4096
	}
	return size
}

func collectAuthenticatedResourceAggregates(ctx context.Context, d *requestContext, target authenticatedReadTarget) (*resourceAggregateWalk, error) {
	return collectAuthenticatedResourceAggregatesWithLimits(ctx, d, target, resourceAggregateLimits{
		entries: 4096, depth: 32, pathBytes: 1 << 20, batch: 128, duration: time.Second,
	})
}

func collectAuthenticatedResourceAggregatesWithLimits(ctx context.Context, d *requestContext, target authenticatedReadTarget, limits resourceAggregateLimits) (*resourceAggregateWalk, error) {
	if target.Info == nil || !target.Info.IsDir() || target.Index.Config.ResolvedRules.IndexingDisabled || limits.entries < 1 || limits.entries > 4096 || limits.depth < 1 ||
		limits.pathBytes < 1 || limits.batch < 1 || limits.duration <= 0 {
		return nil, nil
	}
	user, userErr := currentAuthenticatedReadUser(d.user, d.token)
	if userErr != nil || !user.Permissions.Browse {
		return nil, errors.ErrAccessDenied
	}
	walk := resourceAggregateWalk{ctx: ctx, user: user, root: target, limits: limits,
		deadline: time.Now().Add(limits.duration), sizes: make(map[string]int64), logical: target.Index.Config.UseLogicalSize}
	_, _, complete := walk.collect(target, 0)
	if resourceAggregateCollectedHook != nil {
		resourceAggregateCollectedHook()
	}
	currentUser, currentErr := currentAuthenticatedReadUser(d.user, d.token)
	if currentErr != nil || !currentUser.Permissions.Browse {
		return nil, errors.ErrAccessDenied
	}
	currentRoot, rootErr := resolveAuthenticatedBrowseTarget(currentUser, target.Index.Name, target.RequestedPath)
	if rootErr != nil || !sameAuthenticatedReadTarget(target, currentRoot) || currentRoot.UserScope != target.UserScope {
		return nil, errors.ErrAccessDenied
	}
	if !complete || !walk.active() || indexing.GetIndex(target.Index.Name) != target.Index || walk.logical != target.Index.Config.UseLogicalSize {
		return nil, nil
	}
	paths := make([]string, 0, len(walk.entries)*2)
	for _, entry := range walk.entries {
		if !walk.active() {
			return nil, nil
		}
		fresh, freshErr := resolveAuthenticatedReadIndexTargetWithScope(currentUser, target.Index, currentRoot.UserScope, entry.target.LogicalPath)
		if freshErr != nil || !sameAuthenticatedReadTarget(entry.target, fresh) || fresh.Info.IsDir() != entry.target.Info.IsDir() ||
			fresh.Info.Size() != entry.target.Info.Size() || !fresh.Info.ModTime().Equal(entry.target.Info.ModTime()) {
			return nil, nil
		}
		size, indexed, supported := target.Index.FreshAggregateEntry(fresh.LogicalPath, fresh.Info)
		if !supported || size != entry.size || indexed != entry.indexed {
			return nil, nil
		}
		paths = append(paths, fresh.LogicalPath, fresh.CanonicalPath)
	}
	walk.paths = paths
	return &walk, nil
}

func (walk *resourceAggregateWalk) apply(user *users.User, target authenticatedReadTarget, info *iteminfo.ExtendedFileInfo) {
	// Collection precedes the handler's existing final user/scope/identity and
	// child filtering checks. Only this short ACL snapshot runs after them.
	if walk == nil || !walk.active() || user == nil || !user.Permissions.Browse ||
		user.ID != walk.user.ID || user.Username != walk.user.Username ||
		target.UserScope != walk.root.UserScope || !sameAuthenticatedReadTarget(walk.root, target) ||
		target.Info.Size() != walk.root.Info.Size() || !target.Info.ModTime().Equal(walk.root.Info.ModTime()) ||
		walk.logical != target.Index.Config.UseLogicalSize ||
		!store.Access.PermittedPathsFresh(target.Index.Path, walk.paths, user.Username) {
		return
	}
	if size, found := walk.sizes[target.LogicalPath]; found {
		info.Size = size
	}
	for i := range info.Folders {
		path := normalizePublicShareIndexPath(utils.JoinPathAsUnix(target.LogicalPath, info.Folders[i].Name))
		if size, found := walk.sizes[path]; found {
			info.Folders[i].Size = size
		}
	}
}
