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
	"github.com/volatiletech/null/v8"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/queries"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
	"github.com/volatiletech/sqlboiler/v4/queries/qmhelper"
	"github.com/volatiletech/strmangle"
)

// Privilege is an object representing the database table.
type Privilege struct {
	ID          string      `boil:"id" json:"id" toml:"id" yaml:"id"`
	Name        null.String `boil:"name" json:"name,omitempty" toml:"name" yaml:"name,omitempty"`
	Description null.String `boil:"description" json:"description,omitempty" toml:"description" yaml:"description,omitempty"`

	R *privilegeR `boil:"-" json:"-" toml:"-" yaml:"-"`
	L privilegeL  `boil:"-" json:"-" toml:"-" yaml:"-"`
}

var PrivilegeColumns = struct {
	ID          string
	Name        string
	Description string
}{
	ID:          "id",
	Name:        "name",
	Description: "description",
}

var PrivilegeTableColumns = struct {
	ID          string
	Name        string
	Description string
}{
	ID:          "privileges.id",
	Name:        "privileges.name",
	Description: "privileges.description",
}

// Generated where

var PrivilegeWhere = struct {
	ID          whereHelperstring
	Name        whereHelpernull_String
	Description whereHelpernull_String
}{
	ID:          whereHelperstring{field: "`privileges`.`id`"},
	Name:        whereHelpernull_String{field: "`privileges`.`name`"},
	Description: whereHelpernull_String{field: "`privileges`.`description`"},
}

// PrivilegeRels is where relationship names are stored.
var PrivilegeRels = struct {
}{}

// privilegeR is where relationships are stored.
type privilegeR struct {
}

// NewStruct creates a new relationship struct
func (*privilegeR) NewStruct() *privilegeR {
	return &privilegeR{}
}

// privilegeL is where Load methods for each relationship are stored.
type privilegeL struct{}

var (
	privilegeAllColumns            = []string{"id", "name", "description"}
	privilegeColumnsWithoutDefault = []string{"id", "name", "description"}
	privilegeColumnsWithDefault    = []string{}
	privilegePrimaryKeyColumns     = []string{"id"}
	privilegeGeneratedColumns      = []string{}
)

type (
	// PrivilegeSlice is an alias for a slice of pointers to Privilege.
	// This should almost always be used instead of []Privilege.
	PrivilegeSlice []*Privilege
	// PrivilegeHook is the signature for custom Privilege hook methods
	PrivilegeHook func(context.Context, boil.ContextExecutor, *Privilege) error

	privilegeQuery struct {
		*queries.Query
	}
)

// Cache for insert, update and upsert
var (
	privilegeType                 = reflect.TypeOf(&Privilege{})
	privilegeMapping              = queries.MakeStructMapping(privilegeType)
	privilegePrimaryKeyMapping, _ = queries.BindMapping(privilegeType, privilegeMapping, privilegePrimaryKeyColumns)
	privilegeInsertCacheMut       sync.RWMutex
	privilegeInsertCache          = make(map[string]insertCache)
	privilegeUpdateCacheMut       sync.RWMutex
	privilegeUpdateCache          = make(map[string]updateCache)
	privilegeUpsertCacheMut       sync.RWMutex
	privilegeUpsertCache          = make(map[string]insertCache)
)

var (
	// Force time package dependency for automated UpdatedAt/CreatedAt.
	_ = time.Second
	// Force qmhelper dependency for where clause generation (which doesn't
	// always happen)
	_ = qmhelper.Where
)

var privilegeAfterSelectMu sync.Mutex
var privilegeAfterSelectHooks []PrivilegeHook

var privilegeBeforeInsertMu sync.Mutex
var privilegeBeforeInsertHooks []PrivilegeHook
var privilegeAfterInsertMu sync.Mutex
var privilegeAfterInsertHooks []PrivilegeHook

var privilegeBeforeUpdateMu sync.Mutex
var privilegeBeforeUpdateHooks []PrivilegeHook
var privilegeAfterUpdateMu sync.Mutex
var privilegeAfterUpdateHooks []PrivilegeHook

var privilegeBeforeDeleteMu sync.Mutex
var privilegeBeforeDeleteHooks []PrivilegeHook
var privilegeAfterDeleteMu sync.Mutex
var privilegeAfterDeleteHooks []PrivilegeHook

var privilegeBeforeUpsertMu sync.Mutex
var privilegeBeforeUpsertHooks []PrivilegeHook
var privilegeAfterUpsertMu sync.Mutex
var privilegeAfterUpsertHooks []PrivilegeHook

// doAfterSelectHooks executes all "after Select" hooks.
func (o *Privilege) doAfterSelectHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range privilegeAfterSelectHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeInsertHooks executes all "before insert" hooks.
func (o *Privilege) doBeforeInsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range privilegeBeforeInsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterInsertHooks executes all "after Insert" hooks.
func (o *Privilege) doAfterInsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range privilegeAfterInsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeUpdateHooks executes all "before Update" hooks.
func (o *Privilege) doBeforeUpdateHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range privilegeBeforeUpdateHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterUpdateHooks executes all "after Update" hooks.
func (o *Privilege) doAfterUpdateHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range privilegeAfterUpdateHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeDeleteHooks executes all "before Delete" hooks.
func (o *Privilege) doBeforeDeleteHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range privilegeBeforeDeleteHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterDeleteHooks executes all "after Delete" hooks.
func (o *Privilege) doAfterDeleteHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range privilegeAfterDeleteHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeUpsertHooks executes all "before Upsert" hooks.
func (o *Privilege) doBeforeUpsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range privilegeBeforeUpsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterUpsertHooks executes all "after Upsert" hooks.
func (o *Privilege) doAfterUpsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range privilegeAfterUpsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// AddPrivilegeHook registers your hook function for all future operations.
func AddPrivilegeHook(hookPoint boil.HookPoint, privilegeHook PrivilegeHook) {
	switch hookPoint {
	case boil.AfterSelectHook:
		privilegeAfterSelectMu.Lock()
		privilegeAfterSelectHooks = append(privilegeAfterSelectHooks, privilegeHook)
		privilegeAfterSelectMu.Unlock()
	case boil.BeforeInsertHook:
		privilegeBeforeInsertMu.Lock()
		privilegeBeforeInsertHooks = append(privilegeBeforeInsertHooks, privilegeHook)
		privilegeBeforeInsertMu.Unlock()
	case boil.AfterInsertHook:
		privilegeAfterInsertMu.Lock()
		privilegeAfterInsertHooks = append(privilegeAfterInsertHooks, privilegeHook)
		privilegeAfterInsertMu.Unlock()
	case boil.BeforeUpdateHook:
		privilegeBeforeUpdateMu.Lock()
		privilegeBeforeUpdateHooks = append(privilegeBeforeUpdateHooks, privilegeHook)
		privilegeBeforeUpdateMu.Unlock()
	case boil.AfterUpdateHook:
		privilegeAfterUpdateMu.Lock()
		privilegeAfterUpdateHooks = append(privilegeAfterUpdateHooks, privilegeHook)
		privilegeAfterUpdateMu.Unlock()
	case boil.BeforeDeleteHook:
		privilegeBeforeDeleteMu.Lock()
		privilegeBeforeDeleteHooks = append(privilegeBeforeDeleteHooks, privilegeHook)
		privilegeBeforeDeleteMu.Unlock()
	case boil.AfterDeleteHook:
		privilegeAfterDeleteMu.Lock()
		privilegeAfterDeleteHooks = append(privilegeAfterDeleteHooks, privilegeHook)
		privilegeAfterDeleteMu.Unlock()
	case boil.BeforeUpsertHook:
		privilegeBeforeUpsertMu.Lock()
		privilegeBeforeUpsertHooks = append(privilegeBeforeUpsertHooks, privilegeHook)
		privilegeBeforeUpsertMu.Unlock()
	case boil.AfterUpsertHook:
		privilegeAfterUpsertMu.Lock()
		privilegeAfterUpsertHooks = append(privilegeAfterUpsertHooks, privilegeHook)
		privilegeAfterUpsertMu.Unlock()
	}
}

// One returns a single privilege record from the query.
func (q privilegeQuery) One(ctx context.Context, exec boil.ContextExecutor) (*Privilege, error) {
	o := &Privilege{}

	queries.SetLimit(q.Query, 1)

	err := q.Bind(ctx, exec, o)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, errors.Wrap(err, "models: failed to execute a one query for privileges")
	}

	if err := o.doAfterSelectHooks(ctx, exec); err != nil {
		return o, err
	}

	return o, nil
}

// All returns all Privilege records from the query.
func (q privilegeQuery) All(ctx context.Context, exec boil.ContextExecutor) (PrivilegeSlice, error) {
	var o []*Privilege

	err := q.Bind(ctx, exec, &o)
	if err != nil {
		return nil, errors.Wrap(err, "models: failed to assign all query results to Privilege slice")
	}

	if len(privilegeAfterSelectHooks) != 0 {
		for _, obj := range o {
			if err := obj.doAfterSelectHooks(ctx, exec); err != nil {
				return o, err
			}
		}
	}

	return o, nil
}

// Count returns the count of all Privilege records in the query.
func (q privilegeQuery) Count(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	var count int64

	queries.SetSelect(q.Query, nil)
	queries.SetCount(q.Query)

	err := q.Query.QueryRowContext(ctx, exec).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to count privileges rows")
	}

	return count, nil
}

// Exists checks if the row exists in the table.
func (q privilegeQuery) Exists(ctx context.Context, exec boil.ContextExecutor) (bool, error) {
	var count int64

	queries.SetSelect(q.Query, nil)
	queries.SetCount(q.Query)
	queries.SetLimit(q.Query, 1)

	err := q.Query.QueryRowContext(ctx, exec).Scan(&count)
	if err != nil {
		return false, errors.Wrap(err, "models: failed to check if privileges exists")
	}

	return count > 0, nil
}

// Privileges retrieves all the records using an executor.
func Privileges(mods ...qm.QueryMod) privilegeQuery {
	mods = append(mods, qm.From("`privileges`"))
	q := NewQuery(mods...)
	if len(queries.GetSelect(q)) == 0 {
		queries.SetSelect(q, []string{"`privileges`.*"})
	}

	return privilegeQuery{q}
}

// FindPrivilege retrieves a single record by ID with an executor.
// If selectCols is empty Find will return all columns.
func FindPrivilege(ctx context.Context, exec boil.ContextExecutor, iD string, selectCols ...string) (*Privilege, error) {
	privilegeObj := &Privilege{}

	sel := "*"
	if len(selectCols) > 0 {
		sel = strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, selectCols), ",")
	}
	query := fmt.Sprintf(
		"select %s from `privileges` where `id`=?", sel,
	)

	q := queries.Raw(query, iD)

	err := q.Bind(ctx, exec, privilegeObj)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, errors.Wrap(err, "models: unable to select from privileges")
	}

	if err = privilegeObj.doAfterSelectHooks(ctx, exec); err != nil {
		return privilegeObj, err
	}

	return privilegeObj, nil
}

// Insert a single record using an executor.
// See boil.Columns.InsertColumnSet documentation to understand column list inference for inserts.
func (o *Privilege) Insert(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) error {
	if o == nil {
		return errors.New("models: no privileges provided for insertion")
	}

	var err error

	if err := o.doBeforeInsertHooks(ctx, exec); err != nil {
		return err
	}

	nzDefaults := queries.NonZeroDefaultSet(privilegeColumnsWithDefault, o)

	key := makeCacheKey(columns, nzDefaults)
	privilegeInsertCacheMut.RLock()
	cache, cached := privilegeInsertCache[key]
	privilegeInsertCacheMut.RUnlock()

	if !cached {
		wl, returnColumns := columns.InsertColumnSet(
			privilegeAllColumns,
			privilegeColumnsWithDefault,
			privilegeColumnsWithoutDefault,
			nzDefaults,
		)

		cache.valueMapping, err = queries.BindMapping(privilegeType, privilegeMapping, wl)
		if err != nil {
			return err
		}
		cache.retMapping, err = queries.BindMapping(privilegeType, privilegeMapping, returnColumns)
		if err != nil {
			return err
		}
		if len(wl) != 0 {
			cache.query = fmt.Sprintf("INSERT INTO `privileges` (`%s`) %%sVALUES (%s)%%s", strings.Join(wl, "`,`"), strmangle.Placeholders(dialect.UseIndexPlaceholders, len(wl), 1, 1))
		} else {
			cache.query = "INSERT INTO `privileges` () VALUES ()%s%s"
		}

		var queryOutput, queryReturning string

		if len(cache.retMapping) != 0 {
			cache.retQuery = fmt.Sprintf("SELECT `%s` FROM `privileges` WHERE %s", strings.Join(returnColumns, "`,`"), strmangle.WhereClause("`", "`", 0, privilegePrimaryKeyColumns))
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
		return errors.Wrap(err, "models: unable to insert into privileges")
	}

	var identifierCols []interface{}

	if len(cache.retMapping) == 0 {
		goto CacheNoHooks
	}

	identifierCols = []interface{}{
		o.ID,
	}

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, cache.retQuery)
		fmt.Fprintln(writer, identifierCols...)
	}
	err = exec.QueryRowContext(ctx, cache.retQuery, identifierCols...).Scan(queries.PtrsFromMapping(value, cache.retMapping)...)
	if err != nil {
		return errors.Wrap(err, "models: unable to populate default values for privileges")
	}

CacheNoHooks:
	if !cached {
		privilegeInsertCacheMut.Lock()
		privilegeInsertCache[key] = cache
		privilegeInsertCacheMut.Unlock()
	}

	return o.doAfterInsertHooks(ctx, exec)
}

// Update uses an executor to update the Privilege.
// See boil.Columns.UpdateColumnSet documentation to understand column list inference for updates.
// Update does not automatically update the record in case of default values. Use .Reload() to refresh the records.
func (o *Privilege) Update(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) (int64, error) {
	var err error
	if err = o.doBeforeUpdateHooks(ctx, exec); err != nil {
		return 0, err
	}
	key := makeCacheKey(columns, nil)
	privilegeUpdateCacheMut.RLock()
	cache, cached := privilegeUpdateCache[key]
	privilegeUpdateCacheMut.RUnlock()

	if !cached {
		wl := columns.UpdateColumnSet(
			privilegeAllColumns,
			privilegePrimaryKeyColumns,
		)

		if !columns.IsWhitelist() {
			wl = strmangle.SetComplement(wl, []string{"created_at"})
		}
		if len(wl) == 0 {
			return 0, errors.New("models: unable to update privileges, could not build whitelist")
		}

		cache.query = fmt.Sprintf("UPDATE `privileges` SET %s WHERE %s",
			strmangle.SetParamNames("`", "`", 0, wl),
			strmangle.WhereClause("`", "`", 0, privilegePrimaryKeyColumns),
		)
		cache.valueMapping, err = queries.BindMapping(privilegeType, privilegeMapping, append(wl, privilegePrimaryKeyColumns...))
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
		return 0, errors.Wrap(err, "models: unable to update privileges row")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by update for privileges")
	}

	if !cached {
		privilegeUpdateCacheMut.Lock()
		privilegeUpdateCache[key] = cache
		privilegeUpdateCacheMut.Unlock()
	}

	return rowsAff, o.doAfterUpdateHooks(ctx, exec)
}

// UpdateAll updates all rows with the specified column values.
func (q privilegeQuery) UpdateAll(ctx context.Context, exec boil.ContextExecutor, cols M) (int64, error) {
	queries.SetUpdate(q.Query, cols)

	result, err := q.Query.ExecContext(ctx, exec)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update all for privileges")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to retrieve rows affected for privileges")
	}

	return rowsAff, nil
}

// UpdateAll updates all rows with the specified column values, using an executor.
func (o PrivilegeSlice) UpdateAll(ctx context.Context, exec boil.ContextExecutor, cols M) (int64, error) {
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
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), privilegePrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := fmt.Sprintf("UPDATE `privileges` SET %s WHERE %s",
		strmangle.SetParamNames("`", "`", 0, colNames),
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, privilegePrimaryKeyColumns, len(o)))

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args...)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update all in privilege slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to retrieve rows affected all in update all privilege")
	}
	return rowsAff, nil
}

var mySQLPrivilegeUniqueColumns = []string{
	"id",
}

// Upsert attempts an insert using an executor, and does an update or ignore on conflict.
// See boil.Columns documentation for how to properly use updateColumns and insertColumns.
func (o *Privilege) Upsert(ctx context.Context, exec boil.ContextExecutor, updateColumns, insertColumns boil.Columns) error {
	if o == nil {
		return errors.New("models: no privileges provided for upsert")
	}

	if err := o.doBeforeUpsertHooks(ctx, exec); err != nil {
		return err
	}

	nzDefaults := queries.NonZeroDefaultSet(privilegeColumnsWithDefault, o)
	nzUniques := queries.NonZeroDefaultSet(mySQLPrivilegeUniqueColumns, o)

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

	privilegeUpsertCacheMut.RLock()
	cache, cached := privilegeUpsertCache[key]
	privilegeUpsertCacheMut.RUnlock()

	var err error

	if !cached {
		insert, _ := insertColumns.InsertColumnSet(
			privilegeAllColumns,
			privilegeColumnsWithDefault,
			privilegeColumnsWithoutDefault,
			nzDefaults,
		)

		update := updateColumns.UpdateColumnSet(
			privilegeAllColumns,
			privilegePrimaryKeyColumns,
		)

		if !updateColumns.IsNone() && len(update) == 0 {
			return errors.New("models: unable to upsert privileges, could not build update column list")
		}

		ret := strmangle.SetComplement(privilegeAllColumns, strmangle.SetIntersect(insert, update))

		cache.query = buildUpsertQueryMySQL(dialect, "`privileges`", update, insert)
		cache.retQuery = fmt.Sprintf(
			"SELECT %s FROM `privileges` WHERE %s",
			strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, ret), ","),
			strmangle.WhereClause("`", "`", 0, nzUniques),
		)

		cache.valueMapping, err = queries.BindMapping(privilegeType, privilegeMapping, insert)
		if err != nil {
			return err
		}
		if len(ret) != 0 {
			cache.retMapping, err = queries.BindMapping(privilegeType, privilegeMapping, ret)
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
		return errors.Wrap(err, "models: unable to upsert for privileges")
	}

	var uniqueMap []uint64
	var nzUniqueCols []interface{}

	if len(cache.retMapping) == 0 {
		goto CacheNoHooks
	}

	uniqueMap, err = queries.BindMapping(privilegeType, privilegeMapping, nzUniques)
	if err != nil {
		return errors.Wrap(err, "models: unable to retrieve unique values for privileges")
	}
	nzUniqueCols = queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), uniqueMap)

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, cache.retQuery)
		fmt.Fprintln(writer, nzUniqueCols...)
	}
	err = exec.QueryRowContext(ctx, cache.retQuery, nzUniqueCols...).Scan(returns...)
	if err != nil {
		return errors.Wrap(err, "models: unable to populate default values for privileges")
	}

CacheNoHooks:
	if !cached {
		privilegeUpsertCacheMut.Lock()
		privilegeUpsertCache[key] = cache
		privilegeUpsertCacheMut.Unlock()
	}

	return o.doAfterUpsertHooks(ctx, exec)
}

// Delete deletes a single Privilege record with an executor.
// Delete will match against the primary key column to find the record to delete.
func (o *Privilege) Delete(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if o == nil {
		return 0, errors.New("models: no Privilege provided for delete")
	}

	if err := o.doBeforeDeleteHooks(ctx, exec); err != nil {
		return 0, err
	}

	args := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), privilegePrimaryKeyMapping)
	sql := "DELETE FROM `privileges` WHERE `id`=?"

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args...)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete from privileges")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by delete for privileges")
	}

	if err := o.doAfterDeleteHooks(ctx, exec); err != nil {
		return 0, err
	}

	return rowsAff, nil
}

// DeleteAll deletes all matching rows.
func (q privilegeQuery) DeleteAll(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if q.Query == nil {
		return 0, errors.New("models: no privilegeQuery provided for delete all")
	}

	queries.SetDelete(q.Query)

	result, err := q.Query.ExecContext(ctx, exec)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete all from privileges")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by deleteall for privileges")
	}

	return rowsAff, nil
}

// DeleteAll deletes all rows in the slice, using an executor.
func (o PrivilegeSlice) DeleteAll(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if len(o) == 0 {
		return 0, nil
	}

	if len(privilegeBeforeDeleteHooks) != 0 {
		for _, obj := range o {
			if err := obj.doBeforeDeleteHooks(ctx, exec); err != nil {
				return 0, err
			}
		}
	}

	var args []interface{}
	for _, obj := range o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), privilegePrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := "DELETE FROM `privileges` WHERE " +
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, privilegePrimaryKeyColumns, len(o))

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete all from privilege slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by deleteall for privileges")
	}

	if len(privilegeAfterDeleteHooks) != 0 {
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
func (o *Privilege) Reload(ctx context.Context, exec boil.ContextExecutor) error {
	ret, err := FindPrivilege(ctx, exec, o.ID)
	if err != nil {
		return err
	}

	*o = *ret
	return nil
}

// ReloadAll refetches every row with matching primary key column values
// and overwrites the original object slice with the newly updated slice.
func (o *PrivilegeSlice) ReloadAll(ctx context.Context, exec boil.ContextExecutor) error {
	if o == nil || len(*o) == 0 {
		return nil
	}

	slice := PrivilegeSlice{}
	var args []interface{}
	for _, obj := range *o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), privilegePrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := "SELECT `privileges`.* FROM `privileges` WHERE " +
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, privilegePrimaryKeyColumns, len(*o))

	q := queries.Raw(sql, args...)

	err := q.Bind(ctx, exec, &slice)
	if err != nil {
		return errors.Wrap(err, "models: unable to reload all in PrivilegeSlice")
	}

	*o = slice

	return nil
}

// PrivilegeExists checks if the Privilege row exists.
func PrivilegeExists(ctx context.Context, exec boil.ContextExecutor, iD string) (bool, error) {
	var exists bool
	sql := "select exists(select 1 from `privileges` where `id`=? limit 1)"

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, iD)
	}
	row := exec.QueryRowContext(ctx, sql, iD)

	err := row.Scan(&exists)
	if err != nil {
		return false, errors.Wrap(err, "models: unable to check if privileges exists")
	}

	return exists, nil
}

// Exists checks if the Privilege row exists.
func (o *Privilege) Exists(ctx context.Context, exec boil.ContextExecutor) (bool, error) {
	return PrivilegeExists(ctx, exec, o.ID)
}