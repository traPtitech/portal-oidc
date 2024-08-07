// Code generated by SQLBoiler 4.16.2 (https://github.com/volatiletech/sqlboiler). DO NOT EDIT.
// This file is meant to be re-generated in place and/or deleted at any time.

package models

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/friendsofgo/errors"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/queries"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
	"github.com/volatiletech/sqlboiler/v4/queries/qmhelper"
	"github.com/volatiletech/strmangle"
)

// RolesPrivilege is an object representing the database table.
type RolesPrivilege struct {
	RoleID      string `boil:"role_id" json:"role_id" toml:"role_id" yaml:"role_id"`
	PrivilegeID string `boil:"privilege_id" json:"privilege_id" toml:"privilege_id" yaml:"privilege_id"`

	R *rolesPrivilegeR `boil:"-" json:"-" toml:"-" yaml:"-"`
	L rolesPrivilegeL  `boil:"-" json:"-" toml:"-" yaml:"-"`
}

var RolesPrivilegeColumns = struct {
	RoleID      string
	PrivilegeID string
}{
	RoleID:      "role_id",
	PrivilegeID: "privilege_id",
}

var RolesPrivilegeTableColumns = struct {
	RoleID      string
	PrivilegeID string
}{
	RoleID:      "roles_privileges.role_id",
	PrivilegeID: "roles_privileges.privilege_id",
}

// Generated where

var RolesPrivilegeWhere = struct {
	RoleID      whereHelperstring
	PrivilegeID whereHelperstring
}{
	RoleID:      whereHelperstring{field: "`roles_privileges`.`role_id`"},
	PrivilegeID: whereHelperstring{field: "`roles_privileges`.`privilege_id`"},
}

// RolesPrivilegeRels is where relationship names are stored.
var RolesPrivilegeRels = struct {
}{}

// rolesPrivilegeR is where relationships are stored.
type rolesPrivilegeR struct {
}

// NewStruct creates a new relationship struct
func (*rolesPrivilegeR) NewStruct() *rolesPrivilegeR {
	return &rolesPrivilegeR{}
}

// rolesPrivilegeL is where Load methods for each relationship are stored.
type rolesPrivilegeL struct{}

var (
	rolesPrivilegeAllColumns            = []string{"role_id", "privilege_id"}
	rolesPrivilegeColumnsWithoutDefault = []string{"role_id", "privilege_id"}
	rolesPrivilegeColumnsWithDefault    = []string{}
	rolesPrivilegePrimaryKeyColumns     = []string{"role_id", "privilege_id"}
	rolesPrivilegeGeneratedColumns      = []string{}
)

type (
	// RolesPrivilegeSlice is an alias for a slice of pointers to RolesPrivilege.
	// This should almost always be used instead of []RolesPrivilege.
	RolesPrivilegeSlice []*RolesPrivilege
	// RolesPrivilegeHook is the signature for custom RolesPrivilege hook methods
	RolesPrivilegeHook func(context.Context, boil.ContextExecutor, *RolesPrivilege) error

	rolesPrivilegeQuery struct {
		*queries.Query
	}
)

// Cache for insert, update and upsert
var (
	rolesPrivilegeType                 = reflect.TypeOf(&RolesPrivilege{})
	rolesPrivilegeMapping              = queries.MakeStructMapping(rolesPrivilegeType)
	rolesPrivilegePrimaryKeyMapping, _ = queries.BindMapping(rolesPrivilegeType, rolesPrivilegeMapping, rolesPrivilegePrimaryKeyColumns)
	rolesPrivilegeInsertCacheMut       sync.RWMutex
	rolesPrivilegeInsertCache          = make(map[string]insertCache)
	rolesPrivilegeUpdateCacheMut       sync.RWMutex
	rolesPrivilegeUpdateCache          = make(map[string]updateCache)
	rolesPrivilegeUpsertCacheMut       sync.RWMutex
	rolesPrivilegeUpsertCache          = make(map[string]insertCache)
)

var (
	// Force time package dependency for automated UpdatedAt/CreatedAt.
	_ = time.Second
	// Force qmhelper dependency for where clause generation (which doesn't
	// always happen)
	_ = qmhelper.Where
)

var rolesPrivilegeAfterSelectHooks []RolesPrivilegeHook

var rolesPrivilegeBeforeInsertHooks []RolesPrivilegeHook
var rolesPrivilegeAfterInsertHooks []RolesPrivilegeHook

var rolesPrivilegeBeforeUpdateHooks []RolesPrivilegeHook
var rolesPrivilegeAfterUpdateHooks []RolesPrivilegeHook

var rolesPrivilegeBeforeDeleteHooks []RolesPrivilegeHook
var rolesPrivilegeAfterDeleteHooks []RolesPrivilegeHook

var rolesPrivilegeBeforeUpsertHooks []RolesPrivilegeHook
var rolesPrivilegeAfterUpsertHooks []RolesPrivilegeHook

// doAfterSelectHooks executes all "after Select" hooks.
func (o *RolesPrivilege) doAfterSelectHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range rolesPrivilegeAfterSelectHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeInsertHooks executes all "before insert" hooks.
func (o *RolesPrivilege) doBeforeInsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range rolesPrivilegeBeforeInsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterInsertHooks executes all "after Insert" hooks.
func (o *RolesPrivilege) doAfterInsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range rolesPrivilegeAfterInsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeUpdateHooks executes all "before Update" hooks.
func (o *RolesPrivilege) doBeforeUpdateHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range rolesPrivilegeBeforeUpdateHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterUpdateHooks executes all "after Update" hooks.
func (o *RolesPrivilege) doAfterUpdateHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range rolesPrivilegeAfterUpdateHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeDeleteHooks executes all "before Delete" hooks.
func (o *RolesPrivilege) doBeforeDeleteHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range rolesPrivilegeBeforeDeleteHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterDeleteHooks executes all "after Delete" hooks.
func (o *RolesPrivilege) doAfterDeleteHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range rolesPrivilegeAfterDeleteHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeUpsertHooks executes all "before Upsert" hooks.
func (o *RolesPrivilege) doBeforeUpsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range rolesPrivilegeBeforeUpsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterUpsertHooks executes all "after Upsert" hooks.
func (o *RolesPrivilege) doAfterUpsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range rolesPrivilegeAfterUpsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// AddRolesPrivilegeHook registers your hook function for all future operations.
func AddRolesPrivilegeHook(hookPoint boil.HookPoint, rolesPrivilegeHook RolesPrivilegeHook) {
	switch hookPoint {
	case boil.AfterSelectHook:
		rolesPrivilegeAfterSelectHooks = append(rolesPrivilegeAfterSelectHooks, rolesPrivilegeHook)
	case boil.BeforeInsertHook:
		rolesPrivilegeBeforeInsertHooks = append(rolesPrivilegeBeforeInsertHooks, rolesPrivilegeHook)
	case boil.AfterInsertHook:
		rolesPrivilegeAfterInsertHooks = append(rolesPrivilegeAfterInsertHooks, rolesPrivilegeHook)
	case boil.BeforeUpdateHook:
		rolesPrivilegeBeforeUpdateHooks = append(rolesPrivilegeBeforeUpdateHooks, rolesPrivilegeHook)
	case boil.AfterUpdateHook:
		rolesPrivilegeAfterUpdateHooks = append(rolesPrivilegeAfterUpdateHooks, rolesPrivilegeHook)
	case boil.BeforeDeleteHook:
		rolesPrivilegeBeforeDeleteHooks = append(rolesPrivilegeBeforeDeleteHooks, rolesPrivilegeHook)
	case boil.AfterDeleteHook:
		rolesPrivilegeAfterDeleteHooks = append(rolesPrivilegeAfterDeleteHooks, rolesPrivilegeHook)
	case boil.BeforeUpsertHook:
		rolesPrivilegeBeforeUpsertHooks = append(rolesPrivilegeBeforeUpsertHooks, rolesPrivilegeHook)
	case boil.AfterUpsertHook:
		rolesPrivilegeAfterUpsertHooks = append(rolesPrivilegeAfterUpsertHooks, rolesPrivilegeHook)
	}
}

// One returns a single rolesPrivilege record from the query.
func (q rolesPrivilegeQuery) One(ctx context.Context, exec boil.ContextExecutor) (*RolesPrivilege, error) {
	o := &RolesPrivilege{}

	queries.SetLimit(q.Query, 1)

	err := q.Bind(ctx, exec, o)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, errors.Wrap(err, "models: failed to execute a one query for roles_privileges")
	}

	if err := o.doAfterSelectHooks(ctx, exec); err != nil {
		return o, err
	}

	return o, nil
}

// All returns all RolesPrivilege records from the query.
func (q rolesPrivilegeQuery) All(ctx context.Context, exec boil.ContextExecutor) (RolesPrivilegeSlice, error) {
	var o []*RolesPrivilege

	err := q.Bind(ctx, exec, &o)
	if err != nil {
		return nil, errors.Wrap(err, "models: failed to assign all query results to RolesPrivilege slice")
	}

	if len(rolesPrivilegeAfterSelectHooks) != 0 {
		for _, obj := range o {
			if err := obj.doAfterSelectHooks(ctx, exec); err != nil {
				return o, err
			}
		}
	}

	return o, nil
}

// Count returns the count of all RolesPrivilege records in the query.
func (q rolesPrivilegeQuery) Count(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	var count int64

	queries.SetSelect(q.Query, nil)
	queries.SetCount(q.Query)

	err := q.Query.QueryRowContext(ctx, exec).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to count roles_privileges rows")
	}

	return count, nil
}

// Exists checks if the row exists in the table.
func (q rolesPrivilegeQuery) Exists(ctx context.Context, exec boil.ContextExecutor) (bool, error) {
	var count int64

	queries.SetSelect(q.Query, nil)
	queries.SetCount(q.Query)
	queries.SetLimit(q.Query, 1)

	err := q.Query.QueryRowContext(ctx, exec).Scan(&count)
	if err != nil {
		return false, errors.Wrap(err, "models: failed to check if roles_privileges exists")
	}

	return count > 0, nil
}

// RolesPrivileges retrieves all the records using an executor.
func RolesPrivileges(mods ...qm.QueryMod) rolesPrivilegeQuery {
	mods = append(mods, qm.From("`roles_privileges`"))
	q := NewQuery(mods...)
	if len(queries.GetSelect(q)) == 0 {
		queries.SetSelect(q, []string{"`roles_privileges`.*"})
	}

	return rolesPrivilegeQuery{q}
}

// FindRolesPrivilege retrieves a single record by ID with an executor.
// If selectCols is empty Find will return all columns.
func FindRolesPrivilege(ctx context.Context, exec boil.ContextExecutor, roleID string, privilegeID string, selectCols ...string) (*RolesPrivilege, error) {
	rolesPrivilegeObj := &RolesPrivilege{}

	sel := "*"
	if len(selectCols) > 0 {
		sel = strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, selectCols), ",")
	}
	query := fmt.Sprintf(
		"select %s from `roles_privileges` where `role_id`=? AND `privilege_id`=?", sel,
	)

	q := queries.Raw(query, roleID, privilegeID)

	err := q.Bind(ctx, exec, rolesPrivilegeObj)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, errors.Wrap(err, "models: unable to select from roles_privileges")
	}

	if err = rolesPrivilegeObj.doAfterSelectHooks(ctx, exec); err != nil {
		return rolesPrivilegeObj, err
	}

	return rolesPrivilegeObj, nil
}

// Insert a single record using an executor.
// See boil.Columns.InsertColumnSet documentation to understand column list inference for inserts.
func (o *RolesPrivilege) Insert(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) error {
	if o == nil {
		return errors.New("models: no roles_privileges provided for insertion")
	}

	var err error

	if err := o.doBeforeInsertHooks(ctx, exec); err != nil {
		return err
	}

	nzDefaults := queries.NonZeroDefaultSet(rolesPrivilegeColumnsWithDefault, o)

	key := makeCacheKey(columns, nzDefaults)
	rolesPrivilegeInsertCacheMut.RLock()
	cache, cached := rolesPrivilegeInsertCache[key]
	rolesPrivilegeInsertCacheMut.RUnlock()

	if !cached {
		wl, returnColumns := columns.InsertColumnSet(
			rolesPrivilegeAllColumns,
			rolesPrivilegeColumnsWithDefault,
			rolesPrivilegeColumnsWithoutDefault,
			nzDefaults,
		)

		cache.valueMapping, err = queries.BindMapping(rolesPrivilegeType, rolesPrivilegeMapping, wl)
		if err != nil {
			return err
		}
		cache.retMapping, err = queries.BindMapping(rolesPrivilegeType, rolesPrivilegeMapping, returnColumns)
		if err != nil {
			return err
		}
		if len(wl) != 0 {
			cache.query = fmt.Sprintf("INSERT INTO `roles_privileges` (`%s`) %%sVALUES (%s)%%s", strings.Join(wl, "`,`"), strmangle.Placeholders(dialect.UseIndexPlaceholders, len(wl), 1, 1))
		} else {
			cache.query = "INSERT INTO `roles_privileges` () VALUES ()%s%s"
		}

		var queryOutput, queryReturning string

		if len(cache.retMapping) != 0 {
			cache.retQuery = fmt.Sprintf("SELECT `%s` FROM `roles_privileges` WHERE %s", strings.Join(returnColumns, "`,`"), strmangle.WhereClause("`", "`", 0, rolesPrivilegePrimaryKeyColumns))
		}

		cache.query = fmt.Sprintf(cache.query, queryOutput, queryReturning)
	}

	value := reflect.Indirect(reflect.ValueOf(o))
	vals := queries.ValuesFromMapping(value, cache.valueMapping)

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, cache.query)
		fmt.Fprintln(writer, vals)
	}
	_, err = exec.ExecContext(ctx, cache.query, vals...)

	if err != nil {
		return errors.Wrap(err, "models: unable to insert into roles_privileges")
	}

	var identifierCols []interface{}

	if len(cache.retMapping) == 0 {
		goto CacheNoHooks
	}

	identifierCols = []interface{}{
		o.RoleID,
		o.PrivilegeID,
	}

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, cache.retQuery)
		fmt.Fprintln(writer, identifierCols...)
	}
	err = exec.QueryRowContext(ctx, cache.retQuery, identifierCols...).Scan(queries.PtrsFromMapping(value, cache.retMapping)...)
	if err != nil {
		return errors.Wrap(err, "models: unable to populate default values for roles_privileges")
	}

CacheNoHooks:
	if !cached {
		rolesPrivilegeInsertCacheMut.Lock()
		rolesPrivilegeInsertCache[key] = cache
		rolesPrivilegeInsertCacheMut.Unlock()
	}

	return o.doAfterInsertHooks(ctx, exec)
}

// Update uses an executor to update the RolesPrivilege.
// See boil.Columns.UpdateColumnSet documentation to understand column list inference for updates.
// Update does not automatically update the record in case of default values. Use .Reload() to refresh the records.
func (o *RolesPrivilege) Update(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) (int64, error) {
	var err error
	if err = o.doBeforeUpdateHooks(ctx, exec); err != nil {
		return 0, err
	}
	key := makeCacheKey(columns, nil)
	rolesPrivilegeUpdateCacheMut.RLock()
	cache, cached := rolesPrivilegeUpdateCache[key]
	rolesPrivilegeUpdateCacheMut.RUnlock()

	if !cached {
		wl := columns.UpdateColumnSet(
			rolesPrivilegeAllColumns,
			rolesPrivilegePrimaryKeyColumns,
		)

		if !columns.IsWhitelist() {
			wl = strmangle.SetComplement(wl, []string{"created_at"})
		}
		if len(wl) == 0 {
			return 0, errors.New("models: unable to update roles_privileges, could not build whitelist")
		}

		cache.query = fmt.Sprintf("UPDATE `roles_privileges` SET %s WHERE %s",
			strmangle.SetParamNames("`", "`", 0, wl),
			strmangle.WhereClause("`", "`", 0, rolesPrivilegePrimaryKeyColumns),
		)
		cache.valueMapping, err = queries.BindMapping(rolesPrivilegeType, rolesPrivilegeMapping, append(wl, rolesPrivilegePrimaryKeyColumns...))
		if err != nil {
			return 0, err
		}
	}

	values := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), cache.valueMapping)

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, cache.query)
		fmt.Fprintln(writer, values)
	}
	var result sql.Result
	result, err = exec.ExecContext(ctx, cache.query, values...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update roles_privileges row")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by update for roles_privileges")
	}

	if !cached {
		rolesPrivilegeUpdateCacheMut.Lock()
		rolesPrivilegeUpdateCache[key] = cache
		rolesPrivilegeUpdateCacheMut.Unlock()
	}

	return rowsAff, o.doAfterUpdateHooks(ctx, exec)
}

// UpdateAll updates all rows with the specified column values.
func (q rolesPrivilegeQuery) UpdateAll(ctx context.Context, exec boil.ContextExecutor, cols M) (int64, error) {
	queries.SetUpdate(q.Query, cols)

	result, err := q.Query.ExecContext(ctx, exec)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update all for roles_privileges")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to retrieve rows affected for roles_privileges")
	}

	return rowsAff, nil
}

// UpdateAll updates all rows with the specified column values, using an executor.
func (o RolesPrivilegeSlice) UpdateAll(ctx context.Context, exec boil.ContextExecutor, cols M) (int64, error) {
	ln := int64(len(o))
	if ln == 0 {
		return 0, nil
	}

	if len(cols) == 0 {
		return 0, errors.New("models: update all requires at least one column argument")
	}

	colNames := make([]string, len(cols))
	args := make([]interface{}, len(cols))

	i := 0
	for name, value := range cols {
		colNames[i] = name
		args[i] = value
		i++
	}

	// Append all of the primary key values for each column
	for _, obj := range o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), rolesPrivilegePrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := fmt.Sprintf("UPDATE `roles_privileges` SET %s WHERE %s",
		strmangle.SetParamNames("`", "`", 0, colNames),
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, rolesPrivilegePrimaryKeyColumns, len(o)))

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args...)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update all in rolesPrivilege slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to retrieve rows affected all in update all rolesPrivilege")
	}
	return rowsAff, nil
}

var mySQLRolesPrivilegeUniqueColumns = []string{}

// Upsert attempts an insert using an executor, and does an update or ignore on conflict.
// See boil.Columns documentation for how to properly use updateColumns and insertColumns.
func (o *RolesPrivilege) Upsert(ctx context.Context, exec boil.ContextExecutor, updateColumns, insertColumns boil.Columns) error {
	if o == nil {
		return errors.New("models: no roles_privileges provided for upsert")
	}

	if err := o.doBeforeUpsertHooks(ctx, exec); err != nil {
		return err
	}

	nzDefaults := queries.NonZeroDefaultSet(rolesPrivilegeColumnsWithDefault, o)
	nzUniques := queries.NonZeroDefaultSet(mySQLRolesPrivilegeUniqueColumns, o)

	if len(nzUniques) == 0 {
		return errors.New("cannot upsert with a table that cannot conflict on a unique column")
	}

	// Build cache key in-line uglily - mysql vs psql problems
	buf := strmangle.GetBuffer()
	buf.WriteString(strconv.Itoa(updateColumns.Kind))
	for _, c := range updateColumns.Cols {
		buf.WriteString(c)
	}
	buf.WriteByte('.')
	buf.WriteString(strconv.Itoa(insertColumns.Kind))
	for _, c := range insertColumns.Cols {
		buf.WriteString(c)
	}
	buf.WriteByte('.')
	for _, c := range nzDefaults {
		buf.WriteString(c)
	}
	buf.WriteByte('.')
	for _, c := range nzUniques {
		buf.WriteString(c)
	}
	key := buf.String()
	strmangle.PutBuffer(buf)

	rolesPrivilegeUpsertCacheMut.RLock()
	cache, cached := rolesPrivilegeUpsertCache[key]
	rolesPrivilegeUpsertCacheMut.RUnlock()

	var err error

	if !cached {
		insert, _ := insertColumns.InsertColumnSet(
			rolesPrivilegeAllColumns,
			rolesPrivilegeColumnsWithDefault,
			rolesPrivilegeColumnsWithoutDefault,
			nzDefaults,
		)

		update := updateColumns.UpdateColumnSet(
			rolesPrivilegeAllColumns,
			rolesPrivilegePrimaryKeyColumns,
		)

		if !updateColumns.IsNone() && len(update) == 0 {
			return errors.New("models: unable to upsert roles_privileges, could not build update column list")
		}

		ret := strmangle.SetComplement(rolesPrivilegeAllColumns, strmangle.SetIntersect(insert, update))

		cache.query = buildUpsertQueryMySQL(dialect, "`roles_privileges`", update, insert)
		cache.retQuery = fmt.Sprintf(
			"SELECT %s FROM `roles_privileges` WHERE %s",
			strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, ret), ","),
			strmangle.WhereClause("`", "`", 0, nzUniques),
		)

		cache.valueMapping, err = queries.BindMapping(rolesPrivilegeType, rolesPrivilegeMapping, insert)
		if err != nil {
			return err
		}
		if len(ret) != 0 {
			cache.retMapping, err = queries.BindMapping(rolesPrivilegeType, rolesPrivilegeMapping, ret)
			if err != nil {
				return err
			}
		}
	}

	value := reflect.Indirect(reflect.ValueOf(o))
	vals := queries.ValuesFromMapping(value, cache.valueMapping)
	var returns []interface{}
	if len(cache.retMapping) != 0 {
		returns = queries.PtrsFromMapping(value, cache.retMapping)
	}

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, cache.query)
		fmt.Fprintln(writer, vals)
	}
	_, err = exec.ExecContext(ctx, cache.query, vals...)

	if err != nil {
		return errors.Wrap(err, "models: unable to upsert for roles_privileges")
	}

	var uniqueMap []uint64
	var nzUniqueCols []interface{}

	if len(cache.retMapping) == 0 {
		goto CacheNoHooks
	}

	uniqueMap, err = queries.BindMapping(rolesPrivilegeType, rolesPrivilegeMapping, nzUniques)
	if err != nil {
		return errors.Wrap(err, "models: unable to retrieve unique values for roles_privileges")
	}
	nzUniqueCols = queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), uniqueMap)

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, cache.retQuery)
		fmt.Fprintln(writer, nzUniqueCols...)
	}
	err = exec.QueryRowContext(ctx, cache.retQuery, nzUniqueCols...).Scan(returns...)
	if err != nil {
		return errors.Wrap(err, "models: unable to populate default values for roles_privileges")
	}

CacheNoHooks:
	if !cached {
		rolesPrivilegeUpsertCacheMut.Lock()
		rolesPrivilegeUpsertCache[key] = cache
		rolesPrivilegeUpsertCacheMut.Unlock()
	}

	return o.doAfterUpsertHooks(ctx, exec)
}

// Delete deletes a single RolesPrivilege record with an executor.
// Delete will match against the primary key column to find the record to delete.
func (o *RolesPrivilege) Delete(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if o == nil {
		return 0, errors.New("models: no RolesPrivilege provided for delete")
	}

	if err := o.doBeforeDeleteHooks(ctx, exec); err != nil {
		return 0, err
	}

	args := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), rolesPrivilegePrimaryKeyMapping)
	sql := "DELETE FROM `roles_privileges` WHERE `role_id`=? AND `privilege_id`=?"

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args...)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete from roles_privileges")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by delete for roles_privileges")
	}

	if err := o.doAfterDeleteHooks(ctx, exec); err != nil {
		return 0, err
	}

	return rowsAff, nil
}

// DeleteAll deletes all matching rows.
func (q rolesPrivilegeQuery) DeleteAll(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if q.Query == nil {
		return 0, errors.New("models: no rolesPrivilegeQuery provided for delete all")
	}

	queries.SetDelete(q.Query)

	result, err := q.Query.ExecContext(ctx, exec)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete all from roles_privileges")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by deleteall for roles_privileges")
	}

	return rowsAff, nil
}

// DeleteAll deletes all rows in the slice, using an executor.
func (o RolesPrivilegeSlice) DeleteAll(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if len(o) == 0 {
		return 0, nil
	}

	if len(rolesPrivilegeBeforeDeleteHooks) != 0 {
		for _, obj := range o {
			if err := obj.doBeforeDeleteHooks(ctx, exec); err != nil {
				return 0, err
			}
		}
	}

	var args []interface{}
	for _, obj := range o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), rolesPrivilegePrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := "DELETE FROM `roles_privileges` WHERE " +
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, rolesPrivilegePrimaryKeyColumns, len(o))

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete all from rolesPrivilege slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by deleteall for roles_privileges")
	}

	if len(rolesPrivilegeAfterDeleteHooks) != 0 {
		for _, obj := range o {
			if err := obj.doAfterDeleteHooks(ctx, exec); err != nil {
				return 0, err
			}
		}
	}

	return rowsAff, nil
}

// Reload refetches the object from the database
// using the primary keys with an executor.
func (o *RolesPrivilege) Reload(ctx context.Context, exec boil.ContextExecutor) error {
	ret, err := FindRolesPrivilege(ctx, exec, o.RoleID, o.PrivilegeID)
	if err != nil {
		return err
	}

	*o = *ret
	return nil
}

// ReloadAll refetches every row with matching primary key column values
// and overwrites the original object slice with the newly updated slice.
func (o *RolesPrivilegeSlice) ReloadAll(ctx context.Context, exec boil.ContextExecutor) error {
	if o == nil || len(*o) == 0 {
		return nil
	}

	slice := RolesPrivilegeSlice{}
	var args []interface{}
	for _, obj := range *o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), rolesPrivilegePrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := "SELECT `roles_privileges`.* FROM `roles_privileges` WHERE " +
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, rolesPrivilegePrimaryKeyColumns, len(*o))

	q := queries.Raw(sql, args...)

	err := q.Bind(ctx, exec, &slice)
	if err != nil {
		return errors.Wrap(err, "models: unable to reload all in RolesPrivilegeSlice")
	}

	*o = slice

	return nil
}

// RolesPrivilegeExists checks if the RolesPrivilege row exists.
func RolesPrivilegeExists(ctx context.Context, exec boil.ContextExecutor, roleID string, privilegeID string) (bool, error) {
	var exists bool
	sql := "select exists(select 1 from `roles_privileges` where `role_id`=? AND `privilege_id`=? limit 1)"

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, roleID, privilegeID)
	}
	row := exec.QueryRowContext(ctx, sql, roleID, privilegeID)

	err := row.Scan(&exists)
	if err != nil {
		return false, errors.Wrap(err, "models: unable to check if roles_privileges exists")
	}

	return exists, nil
}

// Exists checks if the RolesPrivilege row exists.
func (o *RolesPrivilege) Exists(ctx context.Context, exec boil.ContextExecutor) (bool, error) {
	return RolesPrivilegeExists(ctx, exec, o.RoleID, o.PrivilegeID)
}

// /////////////////////////////// BEGIN EXTENSIONS /////////////////////////////////
// Expose table columns
var (
	RolesPrivilegeAllColumns            = rolesPrivilegeAllColumns
	RolesPrivilegeColumnsWithoutDefault = rolesPrivilegeColumnsWithoutDefault
	RolesPrivilegeColumnsWithDefault    = rolesPrivilegeColumnsWithDefault
	RolesPrivilegePrimaryKeyColumns     = rolesPrivilegePrimaryKeyColumns
	RolesPrivilegeGeneratedColumns      = rolesPrivilegeGeneratedColumns
)

// InsertAll inserts all rows with the specified column values, using an executor.
// IMPORTANT: this will calculate the widest columns from all items in the slice, be careful if you want to use default column values
func (o RolesPrivilegeSlice) InsertAll(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) (int64, error) {
	if len(o) == 0 {
		return 0, nil
	}

	// Calculate the widest columns from all rows need to insert
	wlCols := make(map[string]struct{}, 10)
	for _, row := range o {
		wl, _ := columns.InsertColumnSet(
			rolesPrivilegeAllColumns,
			rolesPrivilegeColumnsWithDefault,
			rolesPrivilegeColumnsWithoutDefault,
			queries.NonZeroDefaultSet(rolesPrivilegeColumnsWithDefault, row),
		)
		for _, col := range wl {
			wlCols[col] = struct{}{}
		}
	}
	wl := make([]string, 0, len(wlCols))
	for _, col := range rolesPrivilegeAllColumns {
		if _, ok := wlCols[col]; ok {
			wl = append(wl, col)
		}
	}

	var sql string
	vals := []interface{}{}
	for i, row := range o {

		if err := row.doBeforeInsertHooks(ctx, exec); err != nil {
			return 0, err
		}

		if i == 0 {
			sql = "INSERT INTO `roles_privileges` " + "(`" + strings.Join(wl, "`,`") + "`)" + " VALUES "
		}
		sql += strmangle.Placeholders(dialect.UseIndexPlaceholders, len(wl), len(vals)+1, len(wl))
		if i != len(o)-1 {
			sql += ","
		}
		valMapping, err := queries.BindMapping(rolesPrivilegeType, rolesPrivilegeMapping, wl)
		if err != nil {
			return 0, err
		}

		value := reflect.Indirect(reflect.ValueOf(row))
		vals = append(vals, queries.ValuesFromMapping(value, valMapping)...)
	}

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, vals)
	}

	result, err := exec.ExecContext(ctx, sql, vals...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to insert all from rolesPrivilege slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by insertall for roles_privileges")
	}

	if len(rolesPrivilegeAfterInsertHooks) != 0 {
		for _, obj := range o {
			if err := obj.doAfterInsertHooks(ctx, exec); err != nil {
				return 0, err
			}
		}
	}

	return rowsAff, nil
}

// InsertIgnoreAll inserts all rows with ignoring the existing ones having the same primary key values.
// IMPORTANT: this will calculate the widest columns from all items in the slice, be careful if you want to use default column values
func (o RolesPrivilegeSlice) InsertIgnoreAll(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) (int64, error) {
	return o.UpsertAll(ctx, exec, boil.None(), columns)
}

// UpsertAll inserts or updates all rows
// Currently it doesn't support "NoContext" and "NoRowsAffected"
// IMPORTANT: this will calculate the widest columns from all items in the slice, be careful if you want to use default column values
func (o RolesPrivilegeSlice) UpsertAll(ctx context.Context, exec boil.ContextExecutor, updateColumns, insertColumns boil.Columns) (int64, error) {
	if len(o) == 0 {
		return 0, nil
	}

	// Calculate the widest columns from all rows need to upsert
	insertCols := make(map[string]struct{}, 10)
	for _, row := range o {
		nzUniques := queries.NonZeroDefaultSet(mySQLRolesPrivilegeUniqueColumns, row)
		if len(nzUniques) == 0 {
			return 0, errors.New("cannot upsert with a table that cannot conflict on a unique column")
		}
		insert, _ := insertColumns.InsertColumnSet(
			rolesPrivilegeAllColumns,
			rolesPrivilegeColumnsWithDefault,
			rolesPrivilegeColumnsWithoutDefault,
			queries.NonZeroDefaultSet(rolesPrivilegeColumnsWithDefault, row),
		)
		for _, col := range insert {
			insertCols[col] = struct{}{}
		}
	}
	insert := make([]string, 0, len(insertCols))
	for _, col := range rolesPrivilegeAllColumns {
		if _, ok := insertCols[col]; ok {
			insert = append(insert, col)
		}
	}

	update := updateColumns.UpdateColumnSet(
		rolesPrivilegeAllColumns,
		rolesPrivilegePrimaryKeyColumns,
	)
	if !updateColumns.IsNone() && len(update) == 0 {
		return 0, errors.New("models: unable to upsert roles_privileges, could not build update column list")
	}

	buf := strmangle.GetBuffer()
	defer strmangle.PutBuffer(buf)

	if len(update) == 0 {
		fmt.Fprintf(
			buf,
			"INSERT IGNORE INTO `roles_privileges`(%s) VALUES %s",
			strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, insert), ","),
			strmangle.Placeholders(false, len(insert)*len(o), 1, len(insert)),
		)
	} else {
		fmt.Fprintf(
			buf,
			"INSERT INTO `roles_privileges`(%s) VALUES %s ON DUPLICATE KEY UPDATE ",
			strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, insert), ","),
			strmangle.Placeholders(false, len(insert)*len(o), 1, len(insert)),
		)

		for i, v := range update {
			if i != 0 {
				buf.WriteByte(',')
			}
			quoted := strmangle.IdentQuote(dialect.LQ, dialect.RQ, v)
			buf.WriteString(quoted)
			buf.WriteString(" = VALUES(")
			buf.WriteString(quoted)
			buf.WriteByte(')')
		}
	}

	query := buf.String()
	valueMapping, err := queries.BindMapping(rolesPrivilegeType, rolesPrivilegeMapping, insert)
	if err != nil {
		return 0, err
	}

	var vals []interface{}
	for _, row := range o {

		if err := row.doBeforeUpsertHooks(ctx, exec); err != nil {
			return 0, err
		}

		value := reflect.Indirect(reflect.ValueOf(row))
		vals = append(vals, queries.ValuesFromMapping(value, valueMapping)...)
	}

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, query)
		fmt.Fprintln(writer, vals)
	}

	result, err := exec.ExecContext(ctx, query, vals...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to upsert for roles_privileges")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by upsert for roles_privileges")
	}

	if len(rolesPrivilegeAfterUpsertHooks) != 0 {
		for _, obj := range o {
			if err := obj.doAfterUpsertHooks(ctx, exec); err != nil {
				return 0, err
			}
		}
	}

	return rowsAff, nil
}

// DeleteAllByPage delete all RolesPrivilege records from the slice.
// This function deletes data by pages to avoid exceeding Mysql limitation (max placeholders: 65535)
// Mysql Error 1390: Prepared statement contains too many placeholders.
func (s RolesPrivilegeSlice) DeleteAllByPage(ctx context.Context, exec boil.ContextExecutor, limits ...int) (int64, error) {
	length := len(s)
	if length == 0 {
		return 0, nil
	}

	// MySQL max placeholders = 65535
	chunkSize := DefaultPageSize
	if len(limits) > 0 && limits[0] > 0 && limits[0] <= MaxPageSize {
		chunkSize = limits[0]
	}
	if length <= chunkSize {
		return s.DeleteAll(ctx, exec)
	}

	rowsAffected := int64(0)
	start := 0
	for {
		end := start + chunkSize
		if end > length {
			end = length
		}
		rows, err := s[start:end].DeleteAll(ctx, exec)
		if err != nil {
			return rowsAffected, err
		}

		rowsAffected += rows
		start = end
		if start >= length {
			break
		}
	}
	return rowsAffected, nil
}

// UpdateAllByPage update all RolesPrivilege records from the slice.
// This function updates data by pages to avoid exceeding Mysql limitation (max placeholders: 65535)
// Mysql Error 1390: Prepared statement contains too many placeholders.
func (s RolesPrivilegeSlice) UpdateAllByPage(ctx context.Context, exec boil.ContextExecutor, cols M, limits ...int) (int64, error) {
	length := len(s)
	if length == 0 {
		return 0, nil
	}

	// MySQL max placeholders = 65535
	// NOTE (eric): len(cols) should not be too big
	chunkSize := DefaultPageSize
	if len(limits) > 0 && limits[0] > 0 && limits[0] <= MaxPageSize {
		chunkSize = limits[0]
	}
	if length <= chunkSize {
		return s.UpdateAll(ctx, exec, cols)
	}

	rowsAffected := int64(0)
	start := 0
	for {
		end := start + chunkSize
		if end > length {
			end = length
		}
		rows, err := s[start:end].UpdateAll(ctx, exec, cols)
		if err != nil {
			return rowsAffected, err
		}

		rowsAffected += rows
		start = end
		if start >= length {
			break
		}
	}
	return rowsAffected, nil
}

// InsertAllByPage insert all RolesPrivilege records from the slice.
// This function inserts data by pages to avoid exceeding Mysql limitation (max placeholders: 65535)
// Mysql Error 1390: Prepared statement contains too many placeholders.
func (s RolesPrivilegeSlice) InsertAllByPage(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns, limits ...int) (int64, error) {
	length := len(s)
	if length == 0 {
		return 0, nil
	}

	// MySQL max placeholders = 65535
	chunkSize := MaxPageSize / reflect.ValueOf(&RolesPrivilegeColumns).Elem().NumField()
	if len(limits) > 0 && limits[0] > 0 && limits[0] < chunkSize {
		chunkSize = limits[0]
	}
	if length <= chunkSize {
		return s.InsertAll(ctx, exec, columns)
	}

	rowsAffected := int64(0)
	start := 0
	for {
		end := start + chunkSize
		if end > length {
			end = length
		}
		rows, err := s[start:end].InsertAll(ctx, exec, columns)
		if err != nil {
			return rowsAffected, err
		}

		rowsAffected += rows
		start = end
		if start >= length {
			break
		}
	}
	return rowsAffected, nil
}

// InsertIgnoreAllByPage insert all RolesPrivilege records from the slice.
// This function inserts data by pages to avoid exceeding Postgres limitation (max parameters: 65535)
func (s RolesPrivilegeSlice) InsertIgnoreAllByPage(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns, limits ...int) (int64, error) {
	length := len(s)
	if length == 0 {
		return 0, nil
	}

	// max number of parameters = 65535
	chunkSize := MaxPageSize / reflect.ValueOf(&RolesPrivilegeColumns).Elem().NumField()
	if len(limits) > 0 && limits[0] > 0 && limits[0] < chunkSize {
		chunkSize = limits[0]
	}
	if length <= chunkSize {
		return s.InsertIgnoreAll(ctx, exec, columns)
	}

	rowsAffected := int64(0)
	start := 0
	for {
		end := start + chunkSize
		if end > length {
			end = length
		}
		rows, err := s[start:end].InsertIgnoreAll(ctx, exec, columns)
		if err != nil {
			return rowsAffected, err
		}

		rowsAffected += rows
		start = end
		if start >= length {
			break
		}
	}
	return rowsAffected, nil
}

// UpsertAllByPage upsert all RolesPrivilege records from the slice.
// This function upserts data by pages to avoid exceeding Mysql limitation (max placeholders: 65535)
// Mysql Error 1390: Prepared statement contains too many placeholders.
func (s RolesPrivilegeSlice) UpsertAllByPage(ctx context.Context, exec boil.ContextExecutor, updateColumns, insertColumns boil.Columns, limits ...int) (int64, error) {
	length := len(s)
	if length == 0 {
		return 0, nil
	}

	// MySQL max placeholders = 65535
	chunkSize := MaxPageSize / reflect.ValueOf(&RolesPrivilegeColumns).Elem().NumField()
	if len(limits) > 0 && limits[0] > 0 && limits[0] < chunkSize {
		chunkSize = limits[0]
	}
	if length <= chunkSize {
		return s.UpsertAll(ctx, exec, updateColumns, insertColumns)
	}

	rowsAffected := int64(0)
	start := 0
	for {
		end := start + chunkSize
		if end > length {
			end = length
		}
		rows, err := s[start:end].UpsertAll(ctx, exec, updateColumns, insertColumns)
		if err != nil {
			return rowsAffected, err
		}

		rowsAffected += rows
		start = end
		if start >= length {
			break
		}
	}
	return rowsAffected, nil
}

///////////////////////////////// END EXTENSIONS /////////////////////////////////
