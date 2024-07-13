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

// User is an object representing the database table.
type User struct {
	ID             string      `boil:"id" json:"id" toml:"id" yaml:"id"`
	Password       null.String `boil:"password" json:"password,omitempty" toml:"password" yaml:"password,omitempty"`
	Salt           null.String `boil:"salt" json:"salt,omitempty" toml:"salt" yaml:"salt,omitempty"`
	Email          null.String `boil:"email" json:"email,omitempty" toml:"email" yaml:"email,omitempty"`
	StudentNumber  null.String `boil:"student_number" json:"student_number,omitempty" toml:"student_number" yaml:"student_number,omitempty"`
	PhoneNumber    null.String `boil:"phone_number" json:"phone_number,omitempty" toml:"phone_number" yaml:"phone_number,omitempty"`
	Postcode       null.String `boil:"postcode" json:"postcode,omitempty" toml:"postcode" yaml:"postcode,omitempty"`
	Address        null.String `boil:"address" json:"address,omitempty" toml:"address" yaml:"address,omitempty"`
	Birthdate      null.String `boil:"birthdate" json:"birthdate,omitempty" toml:"birthdate" yaml:"birthdate,omitempty"`
	Name           null.String `boil:"name" json:"name,omitempty" toml:"name" yaml:"name,omitempty"`
	AlphabeticName null.String `boil:"alphabetic_name" json:"alphabetic_name,omitempty" toml:"alphabetic_name" yaml:"alphabetic_name,omitempty"`
	Nickname       null.String `boil:"nickname" json:"nickname,omitempty" toml:"nickname" yaml:"nickname,omitempty"`
	Sex            null.String `boil:"sex" json:"sex,omitempty" toml:"sex" yaml:"sex,omitempty"`
	StudentPrefix  null.String `boil:"student_prefix" json:"student_prefix,omitempty" toml:"student_prefix" yaml:"student_prefix,omitempty"`
	Department     null.String `boil:"department" json:"department,omitempty" toml:"department" yaml:"department,omitempty"`
	Affiliation    null.String `boil:"affiliation" json:"affiliation,omitempty" toml:"affiliation" yaml:"affiliation,omitempty"`
	CreatedAt      null.Time   `boil:"created_at" json:"created_at,omitempty" toml:"created_at" yaml:"created_at,omitempty"`
	UpdatedAt      null.Time   `boil:"updated_at" json:"updated_at,omitempty" toml:"updated_at" yaml:"updated_at,omitempty"`

	R *userR `boil:"-" json:"-" toml:"-" yaml:"-"`
	L userL  `boil:"-" json:"-" toml:"-" yaml:"-"`
}

var UserColumns = struct {
	ID             string
	Password       string
	Salt           string
	Email          string
	StudentNumber  string
	PhoneNumber    string
	Postcode       string
	Address        string
	Birthdate      string
	Name           string
	AlphabeticName string
	Nickname       string
	Sex            string
	StudentPrefix  string
	Department     string
	Affiliation    string
	CreatedAt      string
	UpdatedAt      string
}{
	ID:             "id",
	Password:       "password",
	Salt:           "salt",
	Email:          "email",
	StudentNumber:  "student_number",
	PhoneNumber:    "phone_number",
	Postcode:       "postcode",
	Address:        "address",
	Birthdate:      "birthdate",
	Name:           "name",
	AlphabeticName: "alphabetic_name",
	Nickname:       "nickname",
	Sex:            "sex",
	StudentPrefix:  "student_prefix",
	Department:     "department",
	Affiliation:    "affiliation",
	CreatedAt:      "created_at",
	UpdatedAt:      "updated_at",
}

var UserTableColumns = struct {
	ID             string
	Password       string
	Salt           string
	Email          string
	StudentNumber  string
	PhoneNumber    string
	Postcode       string
	Address        string
	Birthdate      string
	Name           string
	AlphabeticName string
	Nickname       string
	Sex            string
	StudentPrefix  string
	Department     string
	Affiliation    string
	CreatedAt      string
	UpdatedAt      string
}{
	ID:             "users.id",
	Password:       "users.password",
	Salt:           "users.salt",
	Email:          "users.email",
	StudentNumber:  "users.student_number",
	PhoneNumber:    "users.phone_number",
	Postcode:       "users.postcode",
	Address:        "users.address",
	Birthdate:      "users.birthdate",
	Name:           "users.name",
	AlphabeticName: "users.alphabetic_name",
	Nickname:       "users.nickname",
	Sex:            "users.sex",
	StudentPrefix:  "users.student_prefix",
	Department:     "users.department",
	Affiliation:    "users.affiliation",
	CreatedAt:      "users.created_at",
	UpdatedAt:      "users.updated_at",
}

// Generated where

var UserWhere = struct {
	ID             whereHelperstring
	Password       whereHelpernull_String
	Salt           whereHelpernull_String
	Email          whereHelpernull_String
	StudentNumber  whereHelpernull_String
	PhoneNumber    whereHelpernull_String
	Postcode       whereHelpernull_String
	Address        whereHelpernull_String
	Birthdate      whereHelpernull_String
	Name           whereHelpernull_String
	AlphabeticName whereHelpernull_String
	Nickname       whereHelpernull_String
	Sex            whereHelpernull_String
	StudentPrefix  whereHelpernull_String
	Department     whereHelpernull_String
	Affiliation    whereHelpernull_String
	CreatedAt      whereHelpernull_Time
	UpdatedAt      whereHelpernull_Time
}{
	ID:             whereHelperstring{field: "`users`.`id`"},
	Password:       whereHelpernull_String{field: "`users`.`password`"},
	Salt:           whereHelpernull_String{field: "`users`.`salt`"},
	Email:          whereHelpernull_String{field: "`users`.`email`"},
	StudentNumber:  whereHelpernull_String{field: "`users`.`student_number`"},
	PhoneNumber:    whereHelpernull_String{field: "`users`.`phone_number`"},
	Postcode:       whereHelpernull_String{field: "`users`.`postcode`"},
	Address:        whereHelpernull_String{field: "`users`.`address`"},
	Birthdate:      whereHelpernull_String{field: "`users`.`birthdate`"},
	Name:           whereHelpernull_String{field: "`users`.`name`"},
	AlphabeticName: whereHelpernull_String{field: "`users`.`alphabetic_name`"},
	Nickname:       whereHelpernull_String{field: "`users`.`nickname`"},
	Sex:            whereHelpernull_String{field: "`users`.`sex`"},
	StudentPrefix:  whereHelpernull_String{field: "`users`.`student_prefix`"},
	Department:     whereHelpernull_String{field: "`users`.`department`"},
	Affiliation:    whereHelpernull_String{field: "`users`.`affiliation`"},
	CreatedAt:      whereHelpernull_Time{field: "`users`.`created_at`"},
	UpdatedAt:      whereHelpernull_Time{field: "`users`.`updated_at`"},
}

// UserRels is where relationship names are stored.
var UserRels = struct {
}{}

// userR is where relationships are stored.
type userR struct {
}

// NewStruct creates a new relationship struct
func (*userR) NewStruct() *userR {
	return &userR{}
}

// userL is where Load methods for each relationship are stored.
type userL struct{}

var (
	userAllColumns            = []string{"id", "password", "salt", "email", "student_number", "phone_number", "postcode", "address", "birthdate", "name", "alphabetic_name", "nickname", "sex", "student_prefix", "department", "affiliation", "created_at", "updated_at"}
	userColumnsWithoutDefault = []string{"id", "password", "salt", "email", "student_number", "phone_number", "postcode", "address", "birthdate", "name", "alphabetic_name", "nickname", "sex", "student_prefix", "department", "affiliation", "created_at", "updated_at"}
	userColumnsWithDefault    = []string{}
	userPrimaryKeyColumns     = []string{"id"}
	userGeneratedColumns      = []string{}
)

type (
	// UserSlice is an alias for a slice of pointers to User.
	// This should almost always be used instead of []User.
	UserSlice []*User
	// UserHook is the signature for custom User hook methods
	UserHook func(context.Context, boil.ContextExecutor, *User) error

	userQuery struct {
		*queries.Query
	}
)

// Cache for insert, update and upsert
var (
	userType                 = reflect.TypeOf(&User{})
	userMapping              = queries.MakeStructMapping(userType)
	userPrimaryKeyMapping, _ = queries.BindMapping(userType, userMapping, userPrimaryKeyColumns)
	userInsertCacheMut       sync.RWMutex
	userInsertCache          = make(map[string]insertCache)
	userUpdateCacheMut       sync.RWMutex
	userUpdateCache          = make(map[string]updateCache)
	userUpsertCacheMut       sync.RWMutex
	userUpsertCache          = make(map[string]insertCache)
)

var (
	// Force time package dependency for automated UpdatedAt/CreatedAt.
	_ = time.Second
	// Force qmhelper dependency for where clause generation (which doesn't
	// always happen)
	_ = qmhelper.Where
)

var userAfterSelectMu sync.Mutex
var userAfterSelectHooks []UserHook

var userBeforeInsertMu sync.Mutex
var userBeforeInsertHooks []UserHook
var userAfterInsertMu sync.Mutex
var userAfterInsertHooks []UserHook

var userBeforeUpdateMu sync.Mutex
var userBeforeUpdateHooks []UserHook
var userAfterUpdateMu sync.Mutex
var userAfterUpdateHooks []UserHook

var userBeforeDeleteMu sync.Mutex
var userBeforeDeleteHooks []UserHook
var userAfterDeleteMu sync.Mutex
var userAfterDeleteHooks []UserHook

var userBeforeUpsertMu sync.Mutex
var userBeforeUpsertHooks []UserHook
var userAfterUpsertMu sync.Mutex
var userAfterUpsertHooks []UserHook

// doAfterSelectHooks executes all "after Select" hooks.
func (o *User) doAfterSelectHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userAfterSelectHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeInsertHooks executes all "before insert" hooks.
func (o *User) doBeforeInsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userBeforeInsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterInsertHooks executes all "after Insert" hooks.
func (o *User) doAfterInsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userAfterInsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeUpdateHooks executes all "before Update" hooks.
func (o *User) doBeforeUpdateHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userBeforeUpdateHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterUpdateHooks executes all "after Update" hooks.
func (o *User) doAfterUpdateHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userAfterUpdateHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeDeleteHooks executes all "before Delete" hooks.
func (o *User) doBeforeDeleteHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userBeforeDeleteHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterDeleteHooks executes all "after Delete" hooks.
func (o *User) doAfterDeleteHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userAfterDeleteHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeUpsertHooks executes all "before Upsert" hooks.
func (o *User) doBeforeUpsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userBeforeUpsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterUpsertHooks executes all "after Upsert" hooks.
func (o *User) doAfterUpsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range userAfterUpsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// AddUserHook registers your hook function for all future operations.
func AddUserHook(hookPoint boil.HookPoint, userHook UserHook) {
	switch hookPoint {
	case boil.AfterSelectHook:
		userAfterSelectMu.Lock()
		userAfterSelectHooks = append(userAfterSelectHooks, userHook)
		userAfterSelectMu.Unlock()
	case boil.BeforeInsertHook:
		userBeforeInsertMu.Lock()
		userBeforeInsertHooks = append(userBeforeInsertHooks, userHook)
		userBeforeInsertMu.Unlock()
	case boil.AfterInsertHook:
		userAfterInsertMu.Lock()
		userAfterInsertHooks = append(userAfterInsertHooks, userHook)
		userAfterInsertMu.Unlock()
	case boil.BeforeUpdateHook:
		userBeforeUpdateMu.Lock()
		userBeforeUpdateHooks = append(userBeforeUpdateHooks, userHook)
		userBeforeUpdateMu.Unlock()
	case boil.AfterUpdateHook:
		userAfterUpdateMu.Lock()
		userAfterUpdateHooks = append(userAfterUpdateHooks, userHook)
		userAfterUpdateMu.Unlock()
	case boil.BeforeDeleteHook:
		userBeforeDeleteMu.Lock()
		userBeforeDeleteHooks = append(userBeforeDeleteHooks, userHook)
		userBeforeDeleteMu.Unlock()
	case boil.AfterDeleteHook:
		userAfterDeleteMu.Lock()
		userAfterDeleteHooks = append(userAfterDeleteHooks, userHook)
		userAfterDeleteMu.Unlock()
	case boil.BeforeUpsertHook:
		userBeforeUpsertMu.Lock()
		userBeforeUpsertHooks = append(userBeforeUpsertHooks, userHook)
		userBeforeUpsertMu.Unlock()
	case boil.AfterUpsertHook:
		userAfterUpsertMu.Lock()
		userAfterUpsertHooks = append(userAfterUpsertHooks, userHook)
		userAfterUpsertMu.Unlock()
	}
}

// One returns a single user record from the query.
func (q userQuery) One(ctx context.Context, exec boil.ContextExecutor) (*User, error) {
	o := &User{}

	queries.SetLimit(q.Query, 1)

	err := q.Bind(ctx, exec, o)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, errors.Wrap(err, "models: failed to execute a one query for users")
	}

	if err := o.doAfterSelectHooks(ctx, exec); err != nil {
		return o, err
	}

	return o, nil
}

// All returns all User records from the query.
func (q userQuery) All(ctx context.Context, exec boil.ContextExecutor) (UserSlice, error) {
	var o []*User

	err := q.Bind(ctx, exec, &o)
	if err != nil {
		return nil, errors.Wrap(err, "models: failed to assign all query results to User slice")
	}

	if len(userAfterSelectHooks) != 0 {
		for _, obj := range o {
			if err := obj.doAfterSelectHooks(ctx, exec); err != nil {
				return o, err
			}
		}
	}

	return o, nil
}

// Count returns the count of all User records in the query.
func (q userQuery) Count(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	var count int64

	queries.SetSelect(q.Query, nil)
	queries.SetCount(q.Query)

	err := q.Query.QueryRowContext(ctx, exec).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to count users rows")
	}

	return count, nil
}

// Exists checks if the row exists in the table.
func (q userQuery) Exists(ctx context.Context, exec boil.ContextExecutor) (bool, error) {
	var count int64

	queries.SetSelect(q.Query, nil)
	queries.SetCount(q.Query)
	queries.SetLimit(q.Query, 1)

	err := q.Query.QueryRowContext(ctx, exec).Scan(&count)
	if err != nil {
		return false, errors.Wrap(err, "models: failed to check if users exists")
	}

	return count > 0, nil
}

// Users retrieves all the records using an executor.
func Users(mods ...qm.QueryMod) userQuery {
	mods = append(mods, qm.From("`users`"))
	q := NewQuery(mods...)
	if len(queries.GetSelect(q)) == 0 {
		queries.SetSelect(q, []string{"`users`.*"})
	}

	return userQuery{q}
}

// FindUser retrieves a single record by ID with an executor.
// If selectCols is empty Find will return all columns.
func FindUser(ctx context.Context, exec boil.ContextExecutor, iD string, selectCols ...string) (*User, error) {
	userObj := &User{}

	sel := "*"
	if len(selectCols) > 0 {
		sel = strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, selectCols), ",")
	}
	query := fmt.Sprintf(
		"select %s from `users` where `id`=?", sel,
	)

	q := queries.Raw(query, iD)

	err := q.Bind(ctx, exec, userObj)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, errors.Wrap(err, "models: unable to select from users")
	}

	if err = userObj.doAfterSelectHooks(ctx, exec); err != nil {
		return userObj, err
	}

	return userObj, nil
}

// Insert a single record using an executor.
// See boil.Columns.InsertColumnSet documentation to understand column list inference for inserts.
func (o *User) Insert(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) error {
	if o == nil {
		return errors.New("models: no users provided for insertion")
	}

	var err error
	if !boil.TimestampsAreSkipped(ctx) {
		currTime := time.Now().In(boil.GetLocation())

		if queries.MustTime(o.CreatedAt).IsZero() {
			queries.SetScanner(&o.CreatedAt, currTime)
		}
		if queries.MustTime(o.UpdatedAt).IsZero() {
			queries.SetScanner(&o.UpdatedAt, currTime)
		}
	}

	if err := o.doBeforeInsertHooks(ctx, exec); err != nil {
		return err
	}

	nzDefaults := queries.NonZeroDefaultSet(userColumnsWithDefault, o)

	key := makeCacheKey(columns, nzDefaults)
	userInsertCacheMut.RLock()
	cache, cached := userInsertCache[key]
	userInsertCacheMut.RUnlock()

	if !cached {
		wl, returnColumns := columns.InsertColumnSet(
			userAllColumns,
			userColumnsWithDefault,
			userColumnsWithoutDefault,
			nzDefaults,
		)

		cache.valueMapping, err = queries.BindMapping(userType, userMapping, wl)
		if err != nil {
			return err
		}
		cache.retMapping, err = queries.BindMapping(userType, userMapping, returnColumns)
		if err != nil {
			return err
		}
		if len(wl) != 0 {
			cache.query = fmt.Sprintf("INSERT INTO `users` (`%s`) %%sVALUES (%s)%%s", strings.Join(wl, "`,`"), strmangle.Placeholders(dialect.UseIndexPlaceholders, len(wl), 1, 1))
		} else {
			cache.query = "INSERT INTO `users` () VALUES ()%s%s"
		}

		var queryOutput, queryReturning string

		if len(cache.retMapping) != 0 {
			cache.retQuery = fmt.Sprintf("SELECT `%s` FROM `users` WHERE %s", strings.Join(returnColumns, "`,`"), strmangle.WhereClause("`", "`", 0, userPrimaryKeyColumns))
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
		return errors.Wrap(err, "models: unable to insert into users")
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
		return errors.Wrap(err, "models: unable to populate default values for users")
	}

CacheNoHooks:
	if !cached {
		userInsertCacheMut.Lock()
		userInsertCache[key] = cache
		userInsertCacheMut.Unlock()
	}

	return o.doAfterInsertHooks(ctx, exec)
}

// Update uses an executor to update the User.
// See boil.Columns.UpdateColumnSet documentation to understand column list inference for updates.
// Update does not automatically update the record in case of default values. Use .Reload() to refresh the records.
func (o *User) Update(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) (int64, error) {
	if !boil.TimestampsAreSkipped(ctx) {
		currTime := time.Now().In(boil.GetLocation())

		queries.SetScanner(&o.UpdatedAt, currTime)
	}

	var err error
	if err = o.doBeforeUpdateHooks(ctx, exec); err != nil {
		return 0, err
	}
	key := makeCacheKey(columns, nil)
	userUpdateCacheMut.RLock()
	cache, cached := userUpdateCache[key]
	userUpdateCacheMut.RUnlock()

	if !cached {
		wl := columns.UpdateColumnSet(
			userAllColumns,
			userPrimaryKeyColumns,
		)

		if !columns.IsWhitelist() {
			wl = strmangle.SetComplement(wl, []string{"created_at"})
		}
		if len(wl) == 0 {
			return 0, errors.New("models: unable to update users, could not build whitelist")
		}

		cache.query = fmt.Sprintf("UPDATE `users` SET %s WHERE %s",
			strmangle.SetParamNames("`", "`", 0, wl),
			strmangle.WhereClause("`", "`", 0, userPrimaryKeyColumns),
		)
		cache.valueMapping, err = queries.BindMapping(userType, userMapping, append(wl, userPrimaryKeyColumns...))
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
		return 0, errors.Wrap(err, "models: unable to update users row")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by update for users")
	}

	if !cached {
		userUpdateCacheMut.Lock()
		userUpdateCache[key] = cache
		userUpdateCacheMut.Unlock()
	}

	return rowsAff, o.doAfterUpdateHooks(ctx, exec)
}

// UpdateAll updates all rows with the specified column values.
func (q userQuery) UpdateAll(ctx context.Context, exec boil.ContextExecutor, cols M) (int64, error) {
	queries.SetUpdate(q.Query, cols)

	result, err := q.Query.ExecContext(ctx, exec)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update all for users")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to retrieve rows affected for users")
	}

	return rowsAff, nil
}

// UpdateAll updates all rows with the specified column values, using an executor.
func (o UserSlice) UpdateAll(ctx context.Context, exec boil.ContextExecutor, cols M) (int64, error) {
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
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), userPrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := fmt.Sprintf("UPDATE `users` SET %s WHERE %s",
		strmangle.SetParamNames("`", "`", 0, colNames),
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, userPrimaryKeyColumns, len(o)))

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args...)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update all in user slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to retrieve rows affected all in update all user")
	}
	return rowsAff, nil
}

var mySQLUserUniqueColumns = []string{
	"id",
	"email",
	"student_number",
}

// Upsert attempts an insert using an executor, and does an update or ignore on conflict.
// See boil.Columns documentation for how to properly use updateColumns and insertColumns.
func (o *User) Upsert(ctx context.Context, exec boil.ContextExecutor, updateColumns, insertColumns boil.Columns) error {
	if o == nil {
		return errors.New("models: no users provided for upsert")
	}
	if !boil.TimestampsAreSkipped(ctx) {
		currTime := time.Now().In(boil.GetLocation())

		if queries.MustTime(o.CreatedAt).IsZero() {
			queries.SetScanner(&o.CreatedAt, currTime)
		}
		queries.SetScanner(&o.UpdatedAt, currTime)
	}

	if err := o.doBeforeUpsertHooks(ctx, exec); err != nil {
		return err
	}

	nzDefaults := queries.NonZeroDefaultSet(userColumnsWithDefault, o)
	nzUniques := queries.NonZeroDefaultSet(mySQLUserUniqueColumns, o)

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

	userUpsertCacheMut.RLock()
	cache, cached := userUpsertCache[key]
	userUpsertCacheMut.RUnlock()

	var err error

	if !cached {
		insert, _ := insertColumns.InsertColumnSet(
			userAllColumns,
			userColumnsWithDefault,
			userColumnsWithoutDefault,
			nzDefaults,
		)

		update := updateColumns.UpdateColumnSet(
			userAllColumns,
			userPrimaryKeyColumns,
		)

		if !updateColumns.IsNone() && len(update) == 0 {
			return errors.New("models: unable to upsert users, could not build update column list")
		}

		ret := strmangle.SetComplement(userAllColumns, strmangle.SetIntersect(insert, update))

		cache.query = buildUpsertQueryMySQL(dialect, "`users`", update, insert)
		cache.retQuery = fmt.Sprintf(
			"SELECT %s FROM `users` WHERE %s",
			strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, ret), ","),
			strmangle.WhereClause("`", "`", 0, nzUniques),
		)

		cache.valueMapping, err = queries.BindMapping(userType, userMapping, insert)
		if err != nil {
			return err
		}
		if len(ret) != 0 {
			cache.retMapping, err = queries.BindMapping(userType, userMapping, ret)
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
		return errors.Wrap(err, "models: unable to upsert for users")
	}

	var uniqueMap []uint64
	var nzUniqueCols []interface{}

	if len(cache.retMapping) == 0 {
		goto CacheNoHooks
	}

	uniqueMap, err = queries.BindMapping(userType, userMapping, nzUniques)
	if err != nil {
		return errors.Wrap(err, "models: unable to retrieve unique values for users")
	}
	nzUniqueCols = queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), uniqueMap)

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, cache.retQuery)
		fmt.Fprintln(writer, nzUniqueCols...)
	}
	err = exec.QueryRowContext(ctx, cache.retQuery, nzUniqueCols...).Scan(returns...)
	if err != nil {
		return errors.Wrap(err, "models: unable to populate default values for users")
	}

CacheNoHooks:
	if !cached {
		userUpsertCacheMut.Lock()
		userUpsertCache[key] = cache
		userUpsertCacheMut.Unlock()
	}

	return o.doAfterUpsertHooks(ctx, exec)
}

// Delete deletes a single User record with an executor.
// Delete will match against the primary key column to find the record to delete.
func (o *User) Delete(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if o == nil {
		return 0, errors.New("models: no User provided for delete")
	}

	if err := o.doBeforeDeleteHooks(ctx, exec); err != nil {
		return 0, err
	}

	args := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), userPrimaryKeyMapping)
	sql := "DELETE FROM `users` WHERE `id`=?"

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args...)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete from users")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by delete for users")
	}

	if err := o.doAfterDeleteHooks(ctx, exec); err != nil {
		return 0, err
	}

	return rowsAff, nil
}

// DeleteAll deletes all matching rows.
func (q userQuery) DeleteAll(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if q.Query == nil {
		return 0, errors.New("models: no userQuery provided for delete all")
	}

	queries.SetDelete(q.Query)

	result, err := q.Query.ExecContext(ctx, exec)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete all from users")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by deleteall for users")
	}

	return rowsAff, nil
}

// DeleteAll deletes all rows in the slice, using an executor.
func (o UserSlice) DeleteAll(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if len(o) == 0 {
		return 0, nil
	}

	if len(userBeforeDeleteHooks) != 0 {
		for _, obj := range o {
			if err := obj.doBeforeDeleteHooks(ctx, exec); err != nil {
				return 0, err
			}
		}
	}

	var args []interface{}
	for _, obj := range o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), userPrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := "DELETE FROM `users` WHERE " +
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, userPrimaryKeyColumns, len(o))

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete all from user slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by deleteall for users")
	}

	if len(userAfterDeleteHooks) != 0 {
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
func (o *User) Reload(ctx context.Context, exec boil.ContextExecutor) error {
	ret, err := FindUser(ctx, exec, o.ID)
	if err != nil {
		return err
	}

	*o = *ret
	return nil
}

// ReloadAll refetches every row with matching primary key column values
// and overwrites the original object slice with the newly updated slice.
func (o *UserSlice) ReloadAll(ctx context.Context, exec boil.ContextExecutor) error {
	if o == nil || len(*o) == 0 {
		return nil
	}

	slice := UserSlice{}
	var args []interface{}
	for _, obj := range *o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), userPrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := "SELECT `users`.* FROM `users` WHERE " +
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, userPrimaryKeyColumns, len(*o))

	q := queries.Raw(sql, args...)

	err := q.Bind(ctx, exec, &slice)
	if err != nil {
		return errors.Wrap(err, "models: unable to reload all in UserSlice")
	}

	*o = slice

	return nil
}

// UserExists checks if the User row exists.
func UserExists(ctx context.Context, exec boil.ContextExecutor, iD string) (bool, error) {
	var exists bool
	sql := "select exists(select 1 from `users` where `id`=? limit 1)"

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, iD)
	}
	row := exec.QueryRowContext(ctx, sql, iD)

	err := row.Scan(&exists)
	if err != nil {
		return false, errors.Wrap(err, "models: unable to check if users exists")
	}

	return exists, nil
}

// Exists checks if the User row exists.
func (o *User) Exists(ctx context.Context, exec boil.ContextExecutor) (bool, error) {
	return UserExists(ctx, exec, o.ID)
}