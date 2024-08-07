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

// UserStatus is an object representing the database table.
type UserStatus struct {
	UserID string      `boil:"user_id" json:"user_id" toml:"user_id" yaml:"user_id"`
	Status string      `boil:"status" json:"status" toml:"status" yaml:"status"`
	Detail null.String `boil:"detail" json:"detail,omitempty" toml:"detail" yaml:"detail,omitempty"`

	R *userStatusR `boil:"-" json:"-" toml:"-" yaml:"-"`
	L userStatusL  `boil:"-" json:"-" toml:"-" yaml:"-"`
}

var UserStatusColumns = struct {
	UserID string
	Status string
	Detail string
}{
	UserID: "user_id",
	Status: "status",
	Detail: "detail",
}

var UserStatusTableColumns = struct {
	UserID string
	Status string
	Detail string
}{
	UserID: "user_statuses.user_id",
	Status: "user_statuses.status",
	Detail: "user_statuses.detail",
}

// Generated where

var UserStatusWhere = struct {
	UserID whereHelperstring
	Status whereHelperstring
	Detail whereHelpernull_String
}{
	UserID: whereHelperstring{field: "`user_statuses`.`user_id`"},
	Status: whereHelperstring{field: "`user_statuses`.`status`"},
	Detail: whereHelpernull_String{field: "`user_statuses`.`detail`"},
}

// UserStatusRels is where relationship names are stored.
var UserStatusRels = struct {
}{}

// userStatusR is where relationships are stored.
type userStatusR struct {
}

// NewStruct creates a new relationship struct
func (*userStatusR) NewStruct() *userStatusR {
	return &userStatusR{}
}

// userStatusL is where Load methods for each relationship are stored.
type userStatusL struct{}

var (
	userStatusAllColumns            = []string{"user_id", "status", "detail"}
	userStatusColumnsWithoutDefault = []string{"user_id", "status", "detail"}
	userStatusColumnsWithDefault    = []string{}
	userStatusPrimaryKeyColumns     = []string{"user_id", "status"}
	userStatusGeneratedColumns      = []string{}
)

type (
	// UserStatusSlice is an alias for a slice of pointers to UserStatus.
	// This should almost always be used instead of []UserStatus.
	UserStatusSlice []*UserStatus
	// UserStatusHook is the signature for custom UserStatus hook methods
	UserStatusHook func(context.Context, boil.ContextExecutor, *UserStatus) error

	userStatusQuery struct {
		*queries.Query
	}
)

// Cache for insert, update and upsert
var (
	userStatusType                 = reflect.TypeOf(&UserStatus{})
	userStatusMapping              = queries.MakeStructMapping(userStatusType)
	userStatusPrimaryKeyMapping, _ = queries.BindMapping(userStatusType, userStatusMapping, userStatusPrimaryKeyColumns)
	userStatusInsertCacheMut       sync.RWMutex
	userStatusInsertCache          = make(map[string]insertCache)
	userStatusUpdateCacheMut       sync.RWMutex
	userStatusUpdateCache          = make(map[string]updateCache)
	userStatusUpsertCacheMut       sync.RWMutex
	userStatusUpsertCache          = make(map[string]insertCache)
)

var (
	// Force time package dependency for automated UpdatedAt/CreatedAt.
	_ = time.Second
	// Force qmhelper dependency for where clause generation (which doesn't
	// always happen)
	_ = qmhelper.Where
)

var userStatusAfterSelectHooks []UserStatusHook

var userStatusBeforeInsertHooks []UserStatusHook
var userStatusAfterInsertHooks []UserStatusHook

var userStatusBeforeUpdateHooks []UserStatusHook
var userStatusAfterUpdateHooks []UserStatusHook

var userStatusBeforeDeleteHooks []UserStatusHook
var userStatusAfterDeleteHooks []UserStatusHook

var userStatusBeforeUpsertHooks []UserStatusHook
var userStatusAfterUpsertHooks []UserStatusHook

// doAfterSelectHooks executes all "after Select" hooks.
func (o *UserStatus) doAfterSelectHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userStatusAfterSelectHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeInsertHooks executes all "before insert" hooks.
func (o *UserStatus) doBeforeInsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userStatusBeforeInsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterInsertHooks executes all "after Insert" hooks.
func (o *UserStatus) doAfterInsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userStatusAfterInsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeUpdateHooks executes all "before Update" hooks.
func (o *UserStatus) doBeforeUpdateHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userStatusBeforeUpdateHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterUpdateHooks executes all "after Update" hooks.
func (o *UserStatus) doAfterUpdateHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userStatusAfterUpdateHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeDeleteHooks executes all "before Delete" hooks.
func (o *UserStatus) doBeforeDeleteHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userStatusBeforeDeleteHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterDeleteHooks executes all "after Delete" hooks.
func (o *UserStatus) doAfterDeleteHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userStatusAfterDeleteHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeUpsertHooks executes all "before Upsert" hooks.
func (o *UserStatus) doBeforeUpsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userStatusBeforeUpsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterUpsertHooks executes all "after Upsert" hooks.
func (o *UserStatus) doAfterUpsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userStatusAfterUpsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// AddUserStatusHook registers your hook function for all future operations.
func AddUserStatusHook(hookPoint boil.HookPoint, userStatusHook UserStatusHook) {
	switch hookPoint {
	case boil.AfterSelectHook:
		userStatusAfterSelectHooks = append(userStatusAfterSelectHooks, userStatusHook)
	case boil.BeforeInsertHook:
		userStatusBeforeInsertHooks = append(userStatusBeforeInsertHooks, userStatusHook)
	case boil.AfterInsertHook:
		userStatusAfterInsertHooks = append(userStatusAfterInsertHooks, userStatusHook)
	case boil.BeforeUpdateHook:
		userStatusBeforeUpdateHooks = append(userStatusBeforeUpdateHooks, userStatusHook)
	case boil.AfterUpdateHook:
		userStatusAfterUpdateHooks = append(userStatusAfterUpdateHooks, userStatusHook)
	case boil.BeforeDeleteHook:
		userStatusBeforeDeleteHooks = append(userStatusBeforeDeleteHooks, userStatusHook)
	case boil.AfterDeleteHook:
		userStatusAfterDeleteHooks = append(userStatusAfterDeleteHooks, userStatusHook)
	case boil.BeforeUpsertHook:
		userStatusBeforeUpsertHooks = append(userStatusBeforeUpsertHooks, userStatusHook)
	case boil.AfterUpsertHook:
		userStatusAfterUpsertHooks = append(userStatusAfterUpsertHooks, userStatusHook)
	}
}

// One returns a single userStatus record from the query.
func (q userStatusQuery) One(ctx context.Context, exec boil.ContextExecutor) (*UserStatus, error) {
	o := &UserStatus{}

	queries.SetLimit(q.Query, 1)

	err := q.Bind(ctx, exec, o)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, errors.Wrap(err, "models: failed to execute a one query for user_statuses")
	}

	if err := o.doAfterSelectHooks(ctx, exec); err != nil {
		return o, err
	}

	return o, nil
}

// All returns all UserStatus records from the query.
func (q userStatusQuery) All(ctx context.Context, exec boil.ContextExecutor) (UserStatusSlice, error) {
	var o []*UserStatus

	err := q.Bind(ctx, exec, &o)
	if err != nil {
		return nil, errors.Wrap(err, "models: failed to assign all query results to UserStatus slice")
	}

	if len(userStatusAfterSelectHooks) != 0 {
		for _, obj := range o {
			if err := obj.doAfterSelectHooks(ctx, exec); err != nil {
				return o, err
			}
		}
	}

	return o, nil
}

// Count returns the count of all UserStatus records in the query.
func (q userStatusQuery) Count(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	var count int64

	queries.SetSelect(q.Query, nil)
	queries.SetCount(q.Query)

	err := q.Query.QueryRowContext(ctx, exec).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to count user_statuses rows")
	}

	return count, nil
}

// Exists checks if the row exists in the table.
func (q userStatusQuery) Exists(ctx context.Context, exec boil.ContextExecutor) (bool, error) {
	var count int64

	queries.SetSelect(q.Query, nil)
	queries.SetCount(q.Query)
	queries.SetLimit(q.Query, 1)

	err := q.Query.QueryRowContext(ctx, exec).Scan(&count)
	if err != nil {
		return false, errors.Wrap(err, "models: failed to check if user_statuses exists")
	}

	return count > 0, nil
}

// UserStatuses retrieves all the records using an executor.
func UserStatuses(mods ...qm.QueryMod) userStatusQuery {
	mods = append(mods, qm.From("`user_statuses`"))
	q := NewQuery(mods...)
	if len(queries.GetSelect(q)) == 0 {
		queries.SetSelect(q, []string{"`user_statuses`.*"})
	}

	return userStatusQuery{q}
}

// FindUserStatus retrieves a single record by ID with an executor.
// If selectCols is empty Find will return all columns.
func FindUserStatus(ctx context.Context, exec boil.ContextExecutor, userID string, status string, selectCols ...string) (*UserStatus, error) {
	userStatusObj := &UserStatus{}

	sel := "*"
	if len(selectCols) > 0 {
		sel = strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, selectCols), ",")
	}
	query := fmt.Sprintf(
		"select %s from `user_statuses` where `user_id`=? AND `status`=?", sel,
	)

	q := queries.Raw(query, userID, status)

	err := q.Bind(ctx, exec, userStatusObj)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, errors.Wrap(err, "models: unable to select from user_statuses")
	}

	if err = userStatusObj.doAfterSelectHooks(ctx, exec); err != nil {
		return userStatusObj, err
	}

	return userStatusObj, nil
}

// Insert a single record using an executor.
// See boil.Columns.InsertColumnSet documentation to understand column list inference for inserts.
func (o *UserStatus) Insert(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) error {
	if o == nil {
		return errors.New("models: no user_statuses provided for insertion")
	}

	var err error

	if err := o.doBeforeInsertHooks(ctx, exec); err != nil {
		return err
	}

	nzDefaults := queries.NonZeroDefaultSet(userStatusColumnsWithDefault, o)

	key := makeCacheKey(columns, nzDefaults)
	userStatusInsertCacheMut.RLock()
	cache, cached := userStatusInsertCache[key]
	userStatusInsertCacheMut.RUnlock()

	if !cached {
		wl, returnColumns := columns.InsertColumnSet(
			userStatusAllColumns,
			userStatusColumnsWithDefault,
			userStatusColumnsWithoutDefault,
			nzDefaults,
		)

		cache.valueMapping, err = queries.BindMapping(userStatusType, userStatusMapping, wl)
		if err != nil {
			return err
		}
		cache.retMapping, err = queries.BindMapping(userStatusType, userStatusMapping, returnColumns)
		if err != nil {
			return err
		}
		if len(wl) != 0 {
			cache.query = fmt.Sprintf("INSERT INTO `user_statuses` (`%s`) %%sVALUES (%s)%%s", strings.Join(wl, "`,`"), strmangle.Placeholders(dialect.UseIndexPlaceholders, len(wl), 1, 1))
		} else {
			cache.query = "INSERT INTO `user_statuses` () VALUES ()%s%s"
		}

		var queryOutput, queryReturning string

		if len(cache.retMapping) != 0 {
			cache.retQuery = fmt.Sprintf("SELECT `%s` FROM `user_statuses` WHERE %s", strings.Join(returnColumns, "`,`"), strmangle.WhereClause("`", "`", 0, userStatusPrimaryKeyColumns))
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
		return errors.Wrap(err, "models: unable to insert into user_statuses")
	}

	var identifierCols []interface{}

	if len(cache.retMapping) == 0 {
		goto CacheNoHooks
	}

	identifierCols = []interface{}{
		o.UserID,
		o.Status,
	}

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, cache.retQuery)
		fmt.Fprintln(writer, identifierCols...)
	}
	err = exec.QueryRowContext(ctx, cache.retQuery, identifierCols...).Scan(queries.PtrsFromMapping(value, cache.retMapping)...)
	if err != nil {
		return errors.Wrap(err, "models: unable to populate default values for user_statuses")
	}

CacheNoHooks:
	if !cached {
		userStatusInsertCacheMut.Lock()
		userStatusInsertCache[key] = cache
		userStatusInsertCacheMut.Unlock()
	}

	return o.doAfterInsertHooks(ctx, exec)
}

// Update uses an executor to update the UserStatus.
// See boil.Columns.UpdateColumnSet documentation to understand column list inference for updates.
// Update does not automatically update the record in case of default values. Use .Reload() to refresh the records.
func (o *UserStatus) Update(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) (int64, error) {
	var err error
	if err = o.doBeforeUpdateHooks(ctx, exec); err != nil {
		return 0, err
	}
	key := makeCacheKey(columns, nil)
	userStatusUpdateCacheMut.RLock()
	cache, cached := userStatusUpdateCache[key]
	userStatusUpdateCacheMut.RUnlock()

	if !cached {
		wl := columns.UpdateColumnSet(
			userStatusAllColumns,
			userStatusPrimaryKeyColumns,
		)

		if !columns.IsWhitelist() {
			wl = strmangle.SetComplement(wl, []string{"created_at"})
		}
		if len(wl) == 0 {
			return 0, errors.New("models: unable to update user_statuses, could not build whitelist")
		}

		cache.query = fmt.Sprintf("UPDATE `user_statuses` SET %s WHERE %s",
			strmangle.SetParamNames("`", "`", 0, wl),
			strmangle.WhereClause("`", "`", 0, userStatusPrimaryKeyColumns),
		)
		cache.valueMapping, err = queries.BindMapping(userStatusType, userStatusMapping, append(wl, userStatusPrimaryKeyColumns...))
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
		return 0, errors.Wrap(err, "models: unable to update user_statuses row")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by update for user_statuses")
	}

	if !cached {
		userStatusUpdateCacheMut.Lock()
		userStatusUpdateCache[key] = cache
		userStatusUpdateCacheMut.Unlock()
	}

	return rowsAff, o.doAfterUpdateHooks(ctx, exec)
}

// UpdateAll updates all rows with the specified column values.
func (q userStatusQuery) UpdateAll(ctx context.Context, exec boil.ContextExecutor, cols M) (int64, error) {
	queries.SetUpdate(q.Query, cols)

	result, err := q.Query.ExecContext(ctx, exec)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update all for user_statuses")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to retrieve rows affected for user_statuses")
	}

	return rowsAff, nil
}

// UpdateAll updates all rows with the specified column values, using an executor.
func (o UserStatusSlice) UpdateAll(ctx context.Context, exec boil.ContextExecutor, cols M) (int64, error) {
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
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), userStatusPrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := fmt.Sprintf("UPDATE `user_statuses` SET %s WHERE %s",
		strmangle.SetParamNames("`", "`", 0, colNames),
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, userStatusPrimaryKeyColumns, len(o)))

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args...)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update all in userStatus slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to retrieve rows affected all in update all userStatus")
	}
	return rowsAff, nil
}

var mySQLUserStatusUniqueColumns = []string{}

// Upsert attempts an insert using an executor, and does an update or ignore on conflict.
// See boil.Columns documentation for how to properly use updateColumns and insertColumns.
func (o *UserStatus) Upsert(ctx context.Context, exec boil.ContextExecutor, updateColumns, insertColumns boil.Columns) error {
	if o == nil {
		return errors.New("models: no user_statuses provided for upsert")
	}

	if err := o.doBeforeUpsertHooks(ctx, exec); err != nil {
		return err
	}

	nzDefaults := queries.NonZeroDefaultSet(userStatusColumnsWithDefault, o)
	nzUniques := queries.NonZeroDefaultSet(mySQLUserStatusUniqueColumns, o)

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

	userStatusUpsertCacheMut.RLock()
	cache, cached := userStatusUpsertCache[key]
	userStatusUpsertCacheMut.RUnlock()

	var err error

	if !cached {
		insert, _ := insertColumns.InsertColumnSet(
			userStatusAllColumns,
			userStatusColumnsWithDefault,
			userStatusColumnsWithoutDefault,
			nzDefaults,
		)

		update := updateColumns.UpdateColumnSet(
			userStatusAllColumns,
			userStatusPrimaryKeyColumns,
		)

		if !updateColumns.IsNone() && len(update) == 0 {
			return errors.New("models: unable to upsert user_statuses, could not build update column list")
		}

		ret := strmangle.SetComplement(userStatusAllColumns, strmangle.SetIntersect(insert, update))

		cache.query = buildUpsertQueryMySQL(dialect, "`user_statuses`", update, insert)
		cache.retQuery = fmt.Sprintf(
			"SELECT %s FROM `user_statuses` WHERE %s",
			strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, ret), ","),
			strmangle.WhereClause("`", "`", 0, nzUniques),
		)

		cache.valueMapping, err = queries.BindMapping(userStatusType, userStatusMapping, insert)
		if err != nil {
			return err
		}
		if len(ret) != 0 {
			cache.retMapping, err = queries.BindMapping(userStatusType, userStatusMapping, ret)
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
		return errors.Wrap(err, "models: unable to upsert for user_statuses")
	}

	var uniqueMap []uint64
	var nzUniqueCols []interface{}

	if len(cache.retMapping) == 0 {
		goto CacheNoHooks
	}

	uniqueMap, err = queries.BindMapping(userStatusType, userStatusMapping, nzUniques)
	if err != nil {
		return errors.Wrap(err, "models: unable to retrieve unique values for user_statuses")
	}
	nzUniqueCols = queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), uniqueMap)

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, cache.retQuery)
		fmt.Fprintln(writer, nzUniqueCols...)
	}
	err = exec.QueryRowContext(ctx, cache.retQuery, nzUniqueCols...).Scan(returns...)
	if err != nil {
		return errors.Wrap(err, "models: unable to populate default values for user_statuses")
	}

CacheNoHooks:
	if !cached {
		userStatusUpsertCacheMut.Lock()
		userStatusUpsertCache[key] = cache
		userStatusUpsertCacheMut.Unlock()
	}

	return o.doAfterUpsertHooks(ctx, exec)
}

// Delete deletes a single UserStatus record with an executor.
// Delete will match against the primary key column to find the record to delete.
func (o *UserStatus) Delete(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if o == nil {
		return 0, errors.New("models: no UserStatus provided for delete")
	}

	if err := o.doBeforeDeleteHooks(ctx, exec); err != nil {
		return 0, err
	}

	args := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), userStatusPrimaryKeyMapping)
	sql := "DELETE FROM `user_statuses` WHERE `user_id`=? AND `status`=?"

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args...)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete from user_statuses")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by delete for user_statuses")
	}

	if err := o.doAfterDeleteHooks(ctx, exec); err != nil {
		return 0, err
	}

	return rowsAff, nil
}

// DeleteAll deletes all matching rows.
func (q userStatusQuery) DeleteAll(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if q.Query == nil {
		return 0, errors.New("models: no userStatusQuery provided for delete all")
	}

	queries.SetDelete(q.Query)

	result, err := q.Query.ExecContext(ctx, exec)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete all from user_statuses")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by deleteall for user_statuses")
	}

	return rowsAff, nil
}

// DeleteAll deletes all rows in the slice, using an executor.
func (o UserStatusSlice) DeleteAll(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if len(o) == 0 {
		return 0, nil
	}

	if len(userStatusBeforeDeleteHooks) != 0 {
		for _, obj := range o {
			if err := obj.doBeforeDeleteHooks(ctx, exec); err != nil {
				return 0, err
			}
		}
	}

	var args []interface{}
	for _, obj := range o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), userStatusPrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := "DELETE FROM `user_statuses` WHERE " +
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, userStatusPrimaryKeyColumns, len(o))

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete all from userStatus slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by deleteall for user_statuses")
	}

	if len(userStatusAfterDeleteHooks) != 0 {
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
func (o *UserStatus) Reload(ctx context.Context, exec boil.ContextExecutor) error {
	ret, err := FindUserStatus(ctx, exec, o.UserID, o.Status)
	if err != nil {
		return err
	}

	*o = *ret
	return nil
}

// ReloadAll refetches every row with matching primary key column values
// and overwrites the original object slice with the newly updated slice.
func (o *UserStatusSlice) ReloadAll(ctx context.Context, exec boil.ContextExecutor) error {
	if o == nil || len(*o) == 0 {
		return nil
	}

	slice := UserStatusSlice{}
	var args []interface{}
	for _, obj := range *o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), userStatusPrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := "SELECT `user_statuses`.* FROM `user_statuses` WHERE " +
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, userStatusPrimaryKeyColumns, len(*o))

	q := queries.Raw(sql, args...)

	err := q.Bind(ctx, exec, &slice)
	if err != nil {
		return errors.Wrap(err, "models: unable to reload all in UserStatusSlice")
	}

	*o = slice

	return nil
}

// UserStatusExists checks if the UserStatus row exists.
func UserStatusExists(ctx context.Context, exec boil.ContextExecutor, userID string, status string) (bool, error) {
	var exists bool
	sql := "select exists(select 1 from `user_statuses` where `user_id`=? AND `status`=? limit 1)"

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, userID, status)
	}
	row := exec.QueryRowContext(ctx, sql, userID, status)

	err := row.Scan(&exists)
	if err != nil {
		return false, errors.Wrap(err, "models: unable to check if user_statuses exists")
	}

	return exists, nil
}

// Exists checks if the UserStatus row exists.
func (o *UserStatus) Exists(ctx context.Context, exec boil.ContextExecutor) (bool, error) {
	return UserStatusExists(ctx, exec, o.UserID, o.Status)
}

// /////////////////////////////// BEGIN EXTENSIONS /////////////////////////////////
// Expose table columns
var (
	UserStatusAllColumns            = userStatusAllColumns
	UserStatusColumnsWithoutDefault = userStatusColumnsWithoutDefault
	UserStatusColumnsWithDefault    = userStatusColumnsWithDefault
	UserStatusPrimaryKeyColumns     = userStatusPrimaryKeyColumns
	UserStatusGeneratedColumns      = userStatusGeneratedColumns
)

// InsertAll inserts all rows with the specified column values, using an executor.
// IMPORTANT: this will calculate the widest columns from all items in the slice, be careful if you want to use default column values
func (o UserStatusSlice) InsertAll(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) (int64, error) {
	if len(o) == 0 {
		return 0, nil
	}

	// Calculate the widest columns from all rows need to insert
	wlCols := make(map[string]struct{}, 10)
	for _, row := range o {
		wl, _ := columns.InsertColumnSet(
			userStatusAllColumns,
			userStatusColumnsWithDefault,
			userStatusColumnsWithoutDefault,
			queries.NonZeroDefaultSet(userStatusColumnsWithDefault, row),
		)
		for _, col := range wl {
			wlCols[col] = struct{}{}
		}
	}
	wl := make([]string, 0, len(wlCols))
	for _, col := range userStatusAllColumns {
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
			sql = "INSERT INTO `user_statuses` " + "(`" + strings.Join(wl, "`,`") + "`)" + " VALUES "
		}
		sql += strmangle.Placeholders(dialect.UseIndexPlaceholders, len(wl), len(vals)+1, len(wl))
		if i != len(o)-1 {
			sql += ","
		}
		valMapping, err := queries.BindMapping(userStatusType, userStatusMapping, wl)
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
		return 0, errors.Wrap(err, "models: unable to insert all from userStatus slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by insertall for user_statuses")
	}

	if len(userStatusAfterInsertHooks) != 0 {
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
func (o UserStatusSlice) InsertIgnoreAll(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) (int64, error) {
	return o.UpsertAll(ctx, exec, boil.None(), columns)
}

// UpsertAll inserts or updates all rows
// Currently it doesn't support "NoContext" and "NoRowsAffected"
// IMPORTANT: this will calculate the widest columns from all items in the slice, be careful if you want to use default column values
func (o UserStatusSlice) UpsertAll(ctx context.Context, exec boil.ContextExecutor, updateColumns, insertColumns boil.Columns) (int64, error) {
	if len(o) == 0 {
		return 0, nil
	}

	// Calculate the widest columns from all rows need to upsert
	insertCols := make(map[string]struct{}, 10)
	for _, row := range o {
		nzUniques := queries.NonZeroDefaultSet(mySQLUserStatusUniqueColumns, row)
		if len(nzUniques) == 0 {
			return 0, errors.New("cannot upsert with a table that cannot conflict on a unique column")
		}
		insert, _ := insertColumns.InsertColumnSet(
			userStatusAllColumns,
			userStatusColumnsWithDefault,
			userStatusColumnsWithoutDefault,
			queries.NonZeroDefaultSet(userStatusColumnsWithDefault, row),
		)
		for _, col := range insert {
			insertCols[col] = struct{}{}
		}
	}
	insert := make([]string, 0, len(insertCols))
	for _, col := range userStatusAllColumns {
		if _, ok := insertCols[col]; ok {
			insert = append(insert, col)
		}
	}

	update := updateColumns.UpdateColumnSet(
		userStatusAllColumns,
		userStatusPrimaryKeyColumns,
	)
	if !updateColumns.IsNone() && len(update) == 0 {
		return 0, errors.New("models: unable to upsert user_statuses, could not build update column list")
	}

	buf := strmangle.GetBuffer()
	defer strmangle.PutBuffer(buf)

	if len(update) == 0 {
		fmt.Fprintf(
			buf,
			"INSERT IGNORE INTO `user_statuses`(%s) VALUES %s",
			strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, insert), ","),
			strmangle.Placeholders(false, len(insert)*len(o), 1, len(insert)),
		)
	} else {
		fmt.Fprintf(
			buf,
			"INSERT INTO `user_statuses`(%s) VALUES %s ON DUPLICATE KEY UPDATE ",
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
	valueMapping, err := queries.BindMapping(userStatusType, userStatusMapping, insert)
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
		return 0, errors.Wrap(err, "models: unable to upsert for user_statuses")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by upsert for user_statuses")
	}

	if len(userStatusAfterUpsertHooks) != 0 {
		for _, obj := range o {
			if err := obj.doAfterUpsertHooks(ctx, exec); err != nil {
				return 0, err
			}
		}
	}

	return rowsAff, nil
}

// DeleteAllByPage delete all UserStatus records from the slice.
// This function deletes data by pages to avoid exceeding Mysql limitation (max placeholders: 65535)
// Mysql Error 1390: Prepared statement contains too many placeholders.
func (s UserStatusSlice) DeleteAllByPage(ctx context.Context, exec boil.ContextExecutor, limits ...int) (int64, error) {
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

// UpdateAllByPage update all UserStatus records from the slice.
// This function updates data by pages to avoid exceeding Mysql limitation (max placeholders: 65535)
// Mysql Error 1390: Prepared statement contains too many placeholders.
func (s UserStatusSlice) UpdateAllByPage(ctx context.Context, exec boil.ContextExecutor, cols M, limits ...int) (int64, error) {
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

// InsertAllByPage insert all UserStatus records from the slice.
// This function inserts data by pages to avoid exceeding Mysql limitation (max placeholders: 65535)
// Mysql Error 1390: Prepared statement contains too many placeholders.
func (s UserStatusSlice) InsertAllByPage(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns, limits ...int) (int64, error) {
	length := len(s)
	if length == 0 {
		return 0, nil
	}

	// MySQL max placeholders = 65535
	chunkSize := MaxPageSize / reflect.ValueOf(&UserStatusColumns).Elem().NumField()
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

// InsertIgnoreAllByPage insert all UserStatus records from the slice.
// This function inserts data by pages to avoid exceeding Postgres limitation (max parameters: 65535)
func (s UserStatusSlice) InsertIgnoreAllByPage(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns, limits ...int) (int64, error) {
	length := len(s)
	if length == 0 {
		return 0, nil
	}

	// max number of parameters = 65535
	chunkSize := MaxPageSize / reflect.ValueOf(&UserStatusColumns).Elem().NumField()
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

// UpsertAllByPage upsert all UserStatus records from the slice.
// This function upserts data by pages to avoid exceeding Mysql limitation (max placeholders: 65535)
// Mysql Error 1390: Prepared statement contains too many placeholders.
func (s UserStatusSlice) UpsertAllByPage(ctx context.Context, exec boil.ContextExecutor, updateColumns, insertColumns boil.Columns, limits ...int) (int64, error) {
	length := len(s)
	if length == 0 {
		return 0, nil
	}

	// MySQL max placeholders = 65535
	chunkSize := MaxPageSize / reflect.ValueOf(&UserStatusColumns).Elem().NumField()
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
