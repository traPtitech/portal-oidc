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

// RedirectURI is an object representing the database table.
type RedirectURI struct {
	ID        string    `boil:"id" json:"id" toml:"id" yaml:"id"`
	ClientID  string    `boil:"client_id" json:"client_id" toml:"client_id" yaml:"client_id"`
	URI       string    `boil:"uri" json:"uri" toml:"uri" yaml:"uri"`
	CreatedAt time.Time `boil:"created_at" json:"created_at" toml:"created_at" yaml:"created_at"`
	UpdatedAt time.Time `boil:"updated_at" json:"updated_at" toml:"updated_at" yaml:"updated_at"`

	R *redirectURIR `boil:"-" json:"-" toml:"-" yaml:"-"`
	L redirectURIL  `boil:"-" json:"-" toml:"-" yaml:"-"`
}

var RedirectURIColumns = struct {
	ID        string
	ClientID  string
	URI       string
	CreatedAt string
	UpdatedAt string
}{
	ID:        "id",
	ClientID:  "client_id",
	URI:       "uri",
	CreatedAt: "created_at",
	UpdatedAt: "updated_at",
}

var RedirectURITableColumns = struct {
	ID        string
	ClientID  string
	URI       string
	CreatedAt string
	UpdatedAt string
}{
	ID:        "redirect_uri.id",
	ClientID:  "redirect_uri.client_id",
	URI:       "redirect_uri.uri",
	CreatedAt: "redirect_uri.created_at",
	UpdatedAt: "redirect_uri.updated_at",
}

// Generated where

var RedirectURIWhere = struct {
	ID        whereHelperstring
	ClientID  whereHelperstring
	URI       whereHelperstring
	CreatedAt whereHelpertime_Time
	UpdatedAt whereHelpertime_Time
}{
	ID:        whereHelperstring{field: "`redirect_uri`.`id`"},
	ClientID:  whereHelperstring{field: "`redirect_uri`.`client_id`"},
	URI:       whereHelperstring{field: "`redirect_uri`.`uri`"},
	CreatedAt: whereHelpertime_Time{field: "`redirect_uri`.`created_at`"},
	UpdatedAt: whereHelpertime_Time{field: "`redirect_uri`.`updated_at`"},
}

// RedirectURIRels is where relationship names are stored.
var RedirectURIRels = struct {
	Client string
}{
	Client: "Client",
}

// redirectURIR is where relationships are stored.
type redirectURIR struct {
	Client *Client `boil:"Client" json:"Client" toml:"Client" yaml:"Client"`
}

// NewStruct creates a new relationship struct
func (*redirectURIR) NewStruct() *redirectURIR {
	return &redirectURIR{}
}

func (r *redirectURIR) GetClient() *Client {
	if r == nil {
		return nil
	}
	return r.Client
}

// redirectURIL is where Load methods for each relationship are stored.
type redirectURIL struct{}

var (
	redirectURIAllColumns            = []string{"id", "client_id", "uri", "created_at", "updated_at"}
	redirectURIColumnsWithoutDefault = []string{"id", "client_id", "uri"}
	redirectURIColumnsWithDefault    = []string{"created_at", "updated_at"}
	redirectURIPrimaryKeyColumns     = []string{"id"}
	redirectURIGeneratedColumns      = []string{}
)

type (
	// RedirectURISlice is an alias for a slice of pointers to RedirectURI.
	// This should almost always be used instead of []RedirectURI.
	RedirectURISlice []*RedirectURI
	// RedirectURIHook is the signature for custom RedirectURI hook methods
	RedirectURIHook func(context.Context, boil.ContextExecutor, *RedirectURI) error

	redirectURIQuery struct {
		*queries.Query
	}
)

// Cache for insert, update and upsert
var (
	redirectURIType                 = reflect.TypeOf(&RedirectURI{})
	redirectURIMapping              = queries.MakeStructMapping(redirectURIType)
	redirectURIPrimaryKeyMapping, _ = queries.BindMapping(redirectURIType, redirectURIMapping, redirectURIPrimaryKeyColumns)
	redirectURIInsertCacheMut       sync.RWMutex
	redirectURIInsertCache          = make(map[string]insertCache)
	redirectURIUpdateCacheMut       sync.RWMutex
	redirectURIUpdateCache          = make(map[string]updateCache)
	redirectURIUpsertCacheMut       sync.RWMutex
	redirectURIUpsertCache          = make(map[string]insertCache)
)

var (
	// Force time package dependency for automated UpdatedAt/CreatedAt.
	_ = time.Second
	// Force qmhelper dependency for where clause generation (which doesn't
	// always happen)
	_ = qmhelper.Where
)

var redirectURIAfterSelectMu sync.Mutex
var redirectURIAfterSelectHooks []RedirectURIHook

var redirectURIBeforeInsertMu sync.Mutex
var redirectURIBeforeInsertHooks []RedirectURIHook
var redirectURIAfterInsertMu sync.Mutex
var redirectURIAfterInsertHooks []RedirectURIHook

var redirectURIBeforeUpdateMu sync.Mutex
var redirectURIBeforeUpdateHooks []RedirectURIHook
var redirectURIAfterUpdateMu sync.Mutex
var redirectURIAfterUpdateHooks []RedirectURIHook

var redirectURIBeforeDeleteMu sync.Mutex
var redirectURIBeforeDeleteHooks []RedirectURIHook
var redirectURIAfterDeleteMu sync.Mutex
var redirectURIAfterDeleteHooks []RedirectURIHook

var redirectURIBeforeUpsertMu sync.Mutex
var redirectURIBeforeUpsertHooks []RedirectURIHook
var redirectURIAfterUpsertMu sync.Mutex
var redirectURIAfterUpsertHooks []RedirectURIHook

// doAfterSelectHooks executes all "after Select" hooks.
func (o *RedirectURI) doAfterSelectHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range redirectURIAfterSelectHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeInsertHooks executes all "before insert" hooks.
func (o *RedirectURI) doBeforeInsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range redirectURIBeforeInsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterInsertHooks executes all "after Insert" hooks.
func (o *RedirectURI) doAfterInsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range redirectURIAfterInsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeUpdateHooks executes all "before Update" hooks.
func (o *RedirectURI) doBeforeUpdateHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range redirectURIBeforeUpdateHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterUpdateHooks executes all "after Update" hooks.
func (o *RedirectURI) doAfterUpdateHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range redirectURIAfterUpdateHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeDeleteHooks executes all "before Delete" hooks.
func (o *RedirectURI) doBeforeDeleteHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range redirectURIBeforeDeleteHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterDeleteHooks executes all "after Delete" hooks.
func (o *RedirectURI) doAfterDeleteHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range redirectURIAfterDeleteHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeUpsertHooks executes all "before Upsert" hooks.
func (o *RedirectURI) doBeforeUpsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range redirectURIBeforeUpsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterUpsertHooks executes all "after Upsert" hooks.
func (o *RedirectURI) doAfterUpsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range redirectURIAfterUpsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// AddRedirectURIHook registers your hook function for all future operations.
func AddRedirectURIHook(hookPoint boil.HookPoint, redirectURIHook RedirectURIHook) {
	switch hookPoint {
	case boil.AfterSelectHook:
		redirectURIAfterSelectMu.Lock()
		redirectURIAfterSelectHooks = append(redirectURIAfterSelectHooks, redirectURIHook)
		redirectURIAfterSelectMu.Unlock()
	case boil.BeforeInsertHook:
		redirectURIBeforeInsertMu.Lock()
		redirectURIBeforeInsertHooks = append(redirectURIBeforeInsertHooks, redirectURIHook)
		redirectURIBeforeInsertMu.Unlock()
	case boil.AfterInsertHook:
		redirectURIAfterInsertMu.Lock()
		redirectURIAfterInsertHooks = append(redirectURIAfterInsertHooks, redirectURIHook)
		redirectURIAfterInsertMu.Unlock()
	case boil.BeforeUpdateHook:
		redirectURIBeforeUpdateMu.Lock()
		redirectURIBeforeUpdateHooks = append(redirectURIBeforeUpdateHooks, redirectURIHook)
		redirectURIBeforeUpdateMu.Unlock()
	case boil.AfterUpdateHook:
		redirectURIAfterUpdateMu.Lock()
		redirectURIAfterUpdateHooks = append(redirectURIAfterUpdateHooks, redirectURIHook)
		redirectURIAfterUpdateMu.Unlock()
	case boil.BeforeDeleteHook:
		redirectURIBeforeDeleteMu.Lock()
		redirectURIBeforeDeleteHooks = append(redirectURIBeforeDeleteHooks, redirectURIHook)
		redirectURIBeforeDeleteMu.Unlock()
	case boil.AfterDeleteHook:
		redirectURIAfterDeleteMu.Lock()
		redirectURIAfterDeleteHooks = append(redirectURIAfterDeleteHooks, redirectURIHook)
		redirectURIAfterDeleteMu.Unlock()
	case boil.BeforeUpsertHook:
		redirectURIBeforeUpsertMu.Lock()
		redirectURIBeforeUpsertHooks = append(redirectURIBeforeUpsertHooks, redirectURIHook)
		redirectURIBeforeUpsertMu.Unlock()
	case boil.AfterUpsertHook:
		redirectURIAfterUpsertMu.Lock()
		redirectURIAfterUpsertHooks = append(redirectURIAfterUpsertHooks, redirectURIHook)
		redirectURIAfterUpsertMu.Unlock()
	}
}

// One returns a single redirectURI record from the query.
func (q redirectURIQuery) One(ctx context.Context, exec boil.ContextExecutor) (*RedirectURI, error) {
	o := &RedirectURI{}

	queries.SetLimit(q.Query, 1)

	err := q.Bind(ctx, exec, o)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, errors.Wrap(err, "models: failed to execute a one query for redirect_uri")
	}

	if err := o.doAfterSelectHooks(ctx, exec); err != nil {
		return o, err
	}

	return o, nil
}

// All returns all RedirectURI records from the query.
func (q redirectURIQuery) All(ctx context.Context, exec boil.ContextExecutor) (RedirectURISlice, error) {
	var o []*RedirectURI

	err := q.Bind(ctx, exec, &o)
	if err != nil {
		return nil, errors.Wrap(err, "models: failed to assign all query results to RedirectURI slice")
	}

	if len(redirectURIAfterSelectHooks) != 0 {
		for _, obj := range o {
			if err := obj.doAfterSelectHooks(ctx, exec); err != nil {
				return o, err
			}
		}
	}

	return o, nil
}

// Count returns the count of all RedirectURI records in the query.
func (q redirectURIQuery) Count(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	var count int64

	queries.SetSelect(q.Query, nil)
	queries.SetCount(q.Query)

	err := q.Query.QueryRowContext(ctx, exec).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to count redirect_uri rows")
	}

	return count, nil
}

// Exists checks if the row exists in the table.
func (q redirectURIQuery) Exists(ctx context.Context, exec boil.ContextExecutor) (bool, error) {
	var count int64

	queries.SetSelect(q.Query, nil)
	queries.SetCount(q.Query)
	queries.SetLimit(q.Query, 1)

	err := q.Query.QueryRowContext(ctx, exec).Scan(&count)
	if err != nil {
		return false, errors.Wrap(err, "models: failed to check if redirect_uri exists")
	}

	return count > 0, nil
}

// Client pointed to by the foreign key.
func (o *RedirectURI) Client(mods ...qm.QueryMod) clientQuery {
	queryMods := []qm.QueryMod{
		qm.Where("`id` = ?", o.ClientID),
	}

	queryMods = append(queryMods, mods...)

	return Clients(queryMods...)
}

// LoadClient allows an eager lookup of values, cached into the
// loaded structs of the objects. This is for an N-1 relationship.
func (redirectURIL) LoadClient(ctx context.Context, e boil.ContextExecutor, singular bool, maybeRedirectURI interface{}, mods queries.Applicator) error {
	var slice []*RedirectURI
	var object *RedirectURI

	if singular {
		var ok bool
		object, ok = maybeRedirectURI.(*RedirectURI)
		if !ok {
			object = new(RedirectURI)
			ok = queries.SetFromEmbeddedStruct(&object, &maybeRedirectURI)
			if !ok {
				return errors.New(fmt.Sprintf("failed to set %T from embedded struct %T", object, maybeRedirectURI))
			}
		}
	} else {
		s, ok := maybeRedirectURI.(*[]*RedirectURI)
		if ok {
			slice = *s
		} else {
			ok = queries.SetFromEmbeddedStruct(&slice, maybeRedirectURI)
			if !ok {
				return errors.New(fmt.Sprintf("failed to set %T from embedded struct %T", slice, maybeRedirectURI))
			}
		}
	}

	args := make(map[interface{}]struct{})
	if singular {
		if object.R == nil {
			object.R = &redirectURIR{}
		}
		args[object.ClientID] = struct{}{}

	} else {
		for _, obj := range slice {
			if obj.R == nil {
				obj.R = &redirectURIR{}
			}

			args[obj.ClientID] = struct{}{}

		}
	}

	if len(args) == 0 {
		return nil
	}

	argsSlice := make([]interface{}, len(args))
	i := 0
	for arg := range args {
		argsSlice[i] = arg
		i++
	}

	query := NewQuery(
		qm.From(`clients`),
		qm.WhereIn(`clients.id in ?`, argsSlice...),
	)
	if mods != nil {
		mods.Apply(query)
	}

	results, err := query.QueryContext(ctx, e)
	if err != nil {
		return errors.Wrap(err, "failed to eager load Client")
	}

	var resultSlice []*Client
	if err = queries.Bind(results, &resultSlice); err != nil {
		return errors.Wrap(err, "failed to bind eager loaded slice Client")
	}

	if err = results.Close(); err != nil {
		return errors.Wrap(err, "failed to close results of eager load for clients")
	}
	if err = results.Err(); err != nil {
		return errors.Wrap(err, "error occurred during iteration of eager loaded relations for clients")
	}

	if len(clientAfterSelectHooks) != 0 {
		for _, obj := range resultSlice {
			if err := obj.doAfterSelectHooks(ctx, e); err != nil {
				return err
			}
		}
	}

	if len(resultSlice) == 0 {
		return nil
	}

	if singular {
		foreign := resultSlice[0]
		object.R.Client = foreign
		if foreign.R == nil {
			foreign.R = &clientR{}
		}
		foreign.R.RedirectUris = append(foreign.R.RedirectUris, object)
		return nil
	}

	for _, local := range slice {
		for _, foreign := range resultSlice {
			if local.ClientID == foreign.ID {
				local.R.Client = foreign
				if foreign.R == nil {
					foreign.R = &clientR{}
				}
				foreign.R.RedirectUris = append(foreign.R.RedirectUris, local)
				break
			}
		}
	}

	return nil
}

// SetClient of the redirectURI to the related item.
// Sets o.R.Client to related.
// Adds o to related.R.RedirectUris.
func (o *RedirectURI) SetClient(ctx context.Context, exec boil.ContextExecutor, insert bool, related *Client) error {
	var err error
	if insert {
		if err = related.Insert(ctx, exec, boil.Infer()); err != nil {
			return errors.Wrap(err, "failed to insert into foreign table")
		}
	}

	updateQuery := fmt.Sprintf(
		"UPDATE `redirect_uri` SET %s WHERE %s",
		strmangle.SetParamNames("`", "`", 0, []string{"client_id"}),
		strmangle.WhereClause("`", "`", 0, redirectURIPrimaryKeyColumns),
	)
	values := []interface{}{related.ID, o.ID}

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, updateQuery)
		fmt.Fprintln(writer, values)
	}
	if _, err = exec.ExecContext(ctx, updateQuery, values...); err != nil {
		return errors.Wrap(err, "failed to update local table")
	}

	o.ClientID = related.ID
	if o.R == nil {
		o.R = &redirectURIR{
			Client: related,
		}
	} else {
		o.R.Client = related
	}

	if related.R == nil {
		related.R = &clientR{
			RedirectUris: RedirectURISlice{o},
		}
	} else {
		related.R.RedirectUris = append(related.R.RedirectUris, o)
	}

	return nil
}

// RedirectUris retrieves all the records using an executor.
func RedirectUris(mods ...qm.QueryMod) redirectURIQuery {
	mods = append(mods, qm.From("`redirect_uri`"))
	q := NewQuery(mods...)
	if len(queries.GetSelect(q)) == 0 {
		queries.SetSelect(q, []string{"`redirect_uri`.*"})
	}

	return redirectURIQuery{q}
}

// FindRedirectURI retrieves a single record by ID with an executor.
// If selectCols is empty Find will return all columns.
func FindRedirectURI(ctx context.Context, exec boil.ContextExecutor, iD string, selectCols ...string) (*RedirectURI, error) {
	redirectURIObj := &RedirectURI{}

	sel := "*"
	if len(selectCols) > 0 {
		sel = strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, selectCols), ",")
	}
	query := fmt.Sprintf(
		"select %s from `redirect_uri` where `id`=?", sel,
	)

	q := queries.Raw(query, iD)

	err := q.Bind(ctx, exec, redirectURIObj)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, errors.Wrap(err, "models: unable to select from redirect_uri")
	}

	if err = redirectURIObj.doAfterSelectHooks(ctx, exec); err != nil {
		return redirectURIObj, err
	}

	return redirectURIObj, nil
}

// Insert a single record using an executor.
// See boil.Columns.InsertColumnSet documentation to understand column list inference for inserts.
func (o *RedirectURI) Insert(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) error {
	if o == nil {
		return errors.New("models: no redirect_uri provided for insertion")
	}

	var err error
	if !boil.TimestampsAreSkipped(ctx) {
		currTime := time.Now().In(boil.GetLocation())

		if o.CreatedAt.IsZero() {
			o.CreatedAt = currTime
		}
		if o.UpdatedAt.IsZero() {
			o.UpdatedAt = currTime
		}
	}

	if err := o.doBeforeInsertHooks(ctx, exec); err != nil {
		return err
	}

	nzDefaults := queries.NonZeroDefaultSet(redirectURIColumnsWithDefault, o)

	key := makeCacheKey(columns, nzDefaults)
	redirectURIInsertCacheMut.RLock()
	cache, cached := redirectURIInsertCache[key]
	redirectURIInsertCacheMut.RUnlock()

	if !cached {
		wl, returnColumns := columns.InsertColumnSet(
			redirectURIAllColumns,
			redirectURIColumnsWithDefault,
			redirectURIColumnsWithoutDefault,
			nzDefaults,
		)

		cache.valueMapping, err = queries.BindMapping(redirectURIType, redirectURIMapping, wl)
		if err != nil {
			return err
		}
		cache.retMapping, err = queries.BindMapping(redirectURIType, redirectURIMapping, returnColumns)
		if err != nil {
			return err
		}
		if len(wl) != 0 {
			cache.query = fmt.Sprintf("INSERT INTO `redirect_uri` (`%s`) %%sVALUES (%s)%%s", strings.Join(wl, "`,`"), strmangle.Placeholders(dialect.UseIndexPlaceholders, len(wl), 1, 1))
		} else {
			cache.query = "INSERT INTO `redirect_uri` () VALUES ()%s%s"
		}

		var queryOutput, queryReturning string

		if len(cache.retMapping) != 0 {
			cache.retQuery = fmt.Sprintf("SELECT `%s` FROM `redirect_uri` WHERE %s", strings.Join(returnColumns, "`,`"), strmangle.WhereClause("`", "`", 0, redirectURIPrimaryKeyColumns))
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
		return errors.Wrap(err, "models: unable to insert into redirect_uri")
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
		return errors.Wrap(err, "models: unable to populate default values for redirect_uri")
	}

CacheNoHooks:
	if !cached {
		redirectURIInsertCacheMut.Lock()
		redirectURIInsertCache[key] = cache
		redirectURIInsertCacheMut.Unlock()
	}

	return o.doAfterInsertHooks(ctx, exec)
}

// Update uses an executor to update the RedirectURI.
// See boil.Columns.UpdateColumnSet documentation to understand column list inference for updates.
// Update does not automatically update the record in case of default values. Use .Reload() to refresh the records.
func (o *RedirectURI) Update(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) (int64, error) {
	if !boil.TimestampsAreSkipped(ctx) {
		currTime := time.Now().In(boil.GetLocation())

		o.UpdatedAt = currTime
	}

	var err error
	if err = o.doBeforeUpdateHooks(ctx, exec); err != nil {
		return 0, err
	}
	key := makeCacheKey(columns, nil)
	redirectURIUpdateCacheMut.RLock()
	cache, cached := redirectURIUpdateCache[key]
	redirectURIUpdateCacheMut.RUnlock()

	if !cached {
		wl := columns.UpdateColumnSet(
			redirectURIAllColumns,
			redirectURIPrimaryKeyColumns,
		)

		if !columns.IsWhitelist() {
			wl = strmangle.SetComplement(wl, []string{"created_at"})
		}
		if len(wl) == 0 {
			return 0, errors.New("models: unable to update redirect_uri, could not build whitelist")
		}

		cache.query = fmt.Sprintf("UPDATE `redirect_uri` SET %s WHERE %s",
			strmangle.SetParamNames("`", "`", 0, wl),
			strmangle.WhereClause("`", "`", 0, redirectURIPrimaryKeyColumns),
		)
		cache.valueMapping, err = queries.BindMapping(redirectURIType, redirectURIMapping, append(wl, redirectURIPrimaryKeyColumns...))
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
		return 0, errors.Wrap(err, "models: unable to update redirect_uri row")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by update for redirect_uri")
	}

	if !cached {
		redirectURIUpdateCacheMut.Lock()
		redirectURIUpdateCache[key] = cache
		redirectURIUpdateCacheMut.Unlock()
	}

	return rowsAff, o.doAfterUpdateHooks(ctx, exec)
}

// UpdateAll updates all rows with the specified column values.
func (q redirectURIQuery) UpdateAll(ctx context.Context, exec boil.ContextExecutor, cols M) (int64, error) {
	queries.SetUpdate(q.Query, cols)

	result, err := q.Query.ExecContext(ctx, exec)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update all for redirect_uri")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to retrieve rows affected for redirect_uri")
	}

	return rowsAff, nil
}

// UpdateAll updates all rows with the specified column values, using an executor.
func (o RedirectURISlice) UpdateAll(ctx context.Context, exec boil.ContextExecutor, cols M) (int64, error) {
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
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), redirectURIPrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := fmt.Sprintf("UPDATE `redirect_uri` SET %s WHERE %s",
		strmangle.SetParamNames("`", "`", 0, colNames),
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, redirectURIPrimaryKeyColumns, len(o)))

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args...)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update all in redirectURI slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to retrieve rows affected all in update all redirectURI")
	}
	return rowsAff, nil
}

var mySQLRedirectURIUniqueColumns = []string{
	"id",
}

// Upsert attempts an insert using an executor, and does an update or ignore on conflict.
// See boil.Columns documentation for how to properly use updateColumns and insertColumns.
func (o *RedirectURI) Upsert(ctx context.Context, exec boil.ContextExecutor, updateColumns, insertColumns boil.Columns) error {
	if o == nil {
		return errors.New("models: no redirect_uri provided for upsert")
	}
	if !boil.TimestampsAreSkipped(ctx) {
		currTime := time.Now().In(boil.GetLocation())

		if o.CreatedAt.IsZero() {
			o.CreatedAt = currTime
		}
		o.UpdatedAt = currTime
	}

	if err := o.doBeforeUpsertHooks(ctx, exec); err != nil {
		return err
	}

	nzDefaults := queries.NonZeroDefaultSet(redirectURIColumnsWithDefault, o)
	nzUniques := queries.NonZeroDefaultSet(mySQLRedirectURIUniqueColumns, o)

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

	redirectURIUpsertCacheMut.RLock()
	cache, cached := redirectURIUpsertCache[key]
	redirectURIUpsertCacheMut.RUnlock()

	var err error

	if !cached {
		insert, _ := insertColumns.InsertColumnSet(
			redirectURIAllColumns,
			redirectURIColumnsWithDefault,
			redirectURIColumnsWithoutDefault,
			nzDefaults,
		)

		update := updateColumns.UpdateColumnSet(
			redirectURIAllColumns,
			redirectURIPrimaryKeyColumns,
		)

		if !updateColumns.IsNone() && len(update) == 0 {
			return errors.New("models: unable to upsert redirect_uri, could not build update column list")
		}

		ret := strmangle.SetComplement(redirectURIAllColumns, strmangle.SetIntersect(insert, update))

		cache.query = buildUpsertQueryMySQL(dialect, "`redirect_uri`", update, insert)
		cache.retQuery = fmt.Sprintf(
			"SELECT %s FROM `redirect_uri` WHERE %s",
			strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, ret), ","),
			strmangle.WhereClause("`", "`", 0, nzUniques),
		)

		cache.valueMapping, err = queries.BindMapping(redirectURIType, redirectURIMapping, insert)
		if err != nil {
			return err
		}
		if len(ret) != 0 {
			cache.retMapping, err = queries.BindMapping(redirectURIType, redirectURIMapping, ret)
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
		return errors.Wrap(err, "models: unable to upsert for redirect_uri")
	}

	var uniqueMap []uint64
	var nzUniqueCols []interface{}

	if len(cache.retMapping) == 0 {
		goto CacheNoHooks
	}

	uniqueMap, err = queries.BindMapping(redirectURIType, redirectURIMapping, nzUniques)
	if err != nil {
		return errors.Wrap(err, "models: unable to retrieve unique values for redirect_uri")
	}
	nzUniqueCols = queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), uniqueMap)

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, cache.retQuery)
		fmt.Fprintln(writer, nzUniqueCols...)
	}
	err = exec.QueryRowContext(ctx, cache.retQuery, nzUniqueCols...).Scan(returns...)
	if err != nil {
		return errors.Wrap(err, "models: unable to populate default values for redirect_uri")
	}

CacheNoHooks:
	if !cached {
		redirectURIUpsertCacheMut.Lock()
		redirectURIUpsertCache[key] = cache
		redirectURIUpsertCacheMut.Unlock()
	}

	return o.doAfterUpsertHooks(ctx, exec)
}

// Delete deletes a single RedirectURI record with an executor.
// Delete will match against the primary key column to find the record to delete.
func (o *RedirectURI) Delete(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if o == nil {
		return 0, errors.New("models: no RedirectURI provided for delete")
	}

	if err := o.doBeforeDeleteHooks(ctx, exec); err != nil {
		return 0, err
	}

	args := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), redirectURIPrimaryKeyMapping)
	sql := "DELETE FROM `redirect_uri` WHERE `id`=?"

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args...)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete from redirect_uri")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by delete for redirect_uri")
	}

	if err := o.doAfterDeleteHooks(ctx, exec); err != nil {
		return 0, err
	}

	return rowsAff, nil
}

// DeleteAll deletes all matching rows.
func (q redirectURIQuery) DeleteAll(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if q.Query == nil {
		return 0, errors.New("models: no redirectURIQuery provided for delete all")
	}

	queries.SetDelete(q.Query)

	result, err := q.Query.ExecContext(ctx, exec)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete all from redirect_uri")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by deleteall for redirect_uri")
	}

	return rowsAff, nil
}

// DeleteAll deletes all rows in the slice, using an executor.
func (o RedirectURISlice) DeleteAll(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if len(o) == 0 {
		return 0, nil
	}

	if len(redirectURIBeforeDeleteHooks) != 0 {
		for _, obj := range o {
			if err := obj.doBeforeDeleteHooks(ctx, exec); err != nil {
				return 0, err
			}
		}
	}

	var args []interface{}
	for _, obj := range o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), redirectURIPrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := "DELETE FROM `redirect_uri` WHERE " +
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, redirectURIPrimaryKeyColumns, len(o))

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete all from redirectURI slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by deleteall for redirect_uri")
	}

	if len(redirectURIAfterDeleteHooks) != 0 {
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
func (o *RedirectURI) Reload(ctx context.Context, exec boil.ContextExecutor) error {
	ret, err := FindRedirectURI(ctx, exec, o.ID)
	if err != nil {
		return err
	}

	*o = *ret
	return nil
}

// ReloadAll refetches every row with matching primary key column values
// and overwrites the original object slice with the newly updated slice.
func (o *RedirectURISlice) ReloadAll(ctx context.Context, exec boil.ContextExecutor) error {
	if o == nil || len(*o) == 0 {
		return nil
	}

	slice := RedirectURISlice{}
	var args []interface{}
	for _, obj := range *o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), redirectURIPrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := "SELECT `redirect_uri`.* FROM `redirect_uri` WHERE " +
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, redirectURIPrimaryKeyColumns, len(*o))

	q := queries.Raw(sql, args...)

	err := q.Bind(ctx, exec, &slice)
	if err != nil {
		return errors.Wrap(err, "models: unable to reload all in RedirectURISlice")
	}

	*o = slice

	return nil
}

// RedirectURIExists checks if the RedirectURI row exists.
func RedirectURIExists(ctx context.Context, exec boil.ContextExecutor, iD string) (bool, error) {
	var exists bool
	sql := "select exists(select 1 from `redirect_uri` where `id`=? limit 1)"

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, iD)
	}
	row := exec.QueryRowContext(ctx, sql, iD)

	err := row.Scan(&exists)
	if err != nil {
		return false, errors.Wrap(err, "models: unable to check if redirect_uri exists")
	}

	return exists, nil
}

// Exists checks if the RedirectURI row exists.
func (o *RedirectURI) Exists(ctx context.Context, exec boil.ContextExecutor) (bool, error) {
	return RedirectURIExists(ctx, exec, o.ID)
}