// Code generated by SQLBoiler 4.16.2 (https://github.com/volatiletech/sqlboiler). DO NOT EDIT.
// This file is meant to be re-generated in place and/or deleted at any time.

package models

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/volatiletech/randomize"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/queries"
	"github.com/volatiletech/strmangle"
)

var (
	// Relationships sometimes use the reflection helper queries.Equal/queries.Assign
	// so force a package dependency in case they don't.
	_ = queries.Equal
)

func testTokensScopes(t *testing.T) {
	t.Parallel()

	query := TokensScopes()

	if query.Query == nil {
		t.Error("expected a query, got nothing")
	}
}

func testTokensScopesDelete(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &TokensScope{}
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if rowsAff, err := o.Delete(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := TokensScopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testTokensScopesQueryDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &TokensScope{}
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if rowsAff, err := TokensScopes().DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := TokensScopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testTokensScopesSliceDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &TokensScope{}
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := TokensScopeSlice{o}

	if rowsAff, err := slice.DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := TokensScopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testTokensScopesExists(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &TokensScope{}
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	e, err := TokensScopeExists(ctx, tx, o.TokenID, o.ScopeID)
	if err != nil {
		t.Errorf("Unable to check if TokensScope exists: %s", err)
	}
	if !e {
		t.Errorf("Expected TokensScopeExists to return true, but got false.")
	}
}

func testTokensScopesFind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &TokensScope{}
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	tokensScopeFound, err := FindTokensScope(ctx, tx, o.TokenID, o.ScopeID)
	if err != nil {
		t.Error(err)
	}

	if tokensScopeFound == nil {
		t.Error("want a record, got nil")
	}
}

func testTokensScopesBind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &TokensScope{}
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if err = TokensScopes().Bind(ctx, tx, o); err != nil {
		t.Error(err)
	}
}

func testTokensScopesOne(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &TokensScope{}
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if x, err := TokensScopes().One(ctx, tx); err != nil {
		t.Error(err)
	} else if x == nil {
		t.Error("expected to get a non nil record")
	}
}

func testTokensScopesAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	tokensScopeOne := &TokensScope{}
	tokensScopeTwo := &TokensScope{}
	if err = randomize.Struct(seed, tokensScopeOne, tokensScopeDBTypes, false, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}
	if err = randomize.Struct(seed, tokensScopeTwo, tokensScopeDBTypes, false, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = tokensScopeOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = tokensScopeTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := TokensScopes().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 2 {
		t.Error("want 2 records, got:", len(slice))
	}
}

func testTokensScopesCount(t *testing.T) {
	t.Parallel()

	var err error
	seed := randomize.NewSeed()
	tokensScopeOne := &TokensScope{}
	tokensScopeTwo := &TokensScope{}
	if err = randomize.Struct(seed, tokensScopeOne, tokensScopeDBTypes, false, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}
	if err = randomize.Struct(seed, tokensScopeTwo, tokensScopeDBTypes, false, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = tokensScopeOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = tokensScopeTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := TokensScopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 2 {
		t.Error("want 2 records, got:", count)
	}
}

func tokensScopeBeforeInsertHook(ctx context.Context, e boil.ContextExecutor, o *TokensScope) error {
	*o = TokensScope{}
	return nil
}

func tokensScopeAfterInsertHook(ctx context.Context, e boil.ContextExecutor, o *TokensScope) error {
	*o = TokensScope{}
	return nil
}

func tokensScopeAfterSelectHook(ctx context.Context, e boil.ContextExecutor, o *TokensScope) error {
	*o = TokensScope{}
	return nil
}

func tokensScopeBeforeUpdateHook(ctx context.Context, e boil.ContextExecutor, o *TokensScope) error {
	*o = TokensScope{}
	return nil
}

func tokensScopeAfterUpdateHook(ctx context.Context, e boil.ContextExecutor, o *TokensScope) error {
	*o = TokensScope{}
	return nil
}

func tokensScopeBeforeDeleteHook(ctx context.Context, e boil.ContextExecutor, o *TokensScope) error {
	*o = TokensScope{}
	return nil
}

func tokensScopeAfterDeleteHook(ctx context.Context, e boil.ContextExecutor, o *TokensScope) error {
	*o = TokensScope{}
	return nil
}

func tokensScopeBeforeUpsertHook(ctx context.Context, e boil.ContextExecutor, o *TokensScope) error {
	*o = TokensScope{}
	return nil
}

func tokensScopeAfterUpsertHook(ctx context.Context, e boil.ContextExecutor, o *TokensScope) error {
	*o = TokensScope{}
	return nil
}

func testTokensScopesHooks(t *testing.T) {
	t.Parallel()

	var err error

	ctx := context.Background()
	empty := &TokensScope{}
	o := &TokensScope{}

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, false); err != nil {
		t.Errorf("Unable to randomize TokensScope object: %s", err)
	}

	AddTokensScopeHook(boil.BeforeInsertHook, tokensScopeBeforeInsertHook)
	if err = o.doBeforeInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeInsertHook function to empty object, but got: %#v", o)
	}
	tokensScopeBeforeInsertHooks = []TokensScopeHook{}

	AddTokensScopeHook(boil.AfterInsertHook, tokensScopeAfterInsertHook)
	if err = o.doAfterInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterInsertHook function to empty object, but got: %#v", o)
	}
	tokensScopeAfterInsertHooks = []TokensScopeHook{}

	AddTokensScopeHook(boil.AfterSelectHook, tokensScopeAfterSelectHook)
	if err = o.doAfterSelectHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterSelectHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterSelectHook function to empty object, but got: %#v", o)
	}
	tokensScopeAfterSelectHooks = []TokensScopeHook{}

	AddTokensScopeHook(boil.BeforeUpdateHook, tokensScopeBeforeUpdateHook)
	if err = o.doBeforeUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpdateHook function to empty object, but got: %#v", o)
	}
	tokensScopeBeforeUpdateHooks = []TokensScopeHook{}

	AddTokensScopeHook(boil.AfterUpdateHook, tokensScopeAfterUpdateHook)
	if err = o.doAfterUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpdateHook function to empty object, but got: %#v", o)
	}
	tokensScopeAfterUpdateHooks = []TokensScopeHook{}

	AddTokensScopeHook(boil.BeforeDeleteHook, tokensScopeBeforeDeleteHook)
	if err = o.doBeforeDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeDeleteHook function to empty object, but got: %#v", o)
	}
	tokensScopeBeforeDeleteHooks = []TokensScopeHook{}

	AddTokensScopeHook(boil.AfterDeleteHook, tokensScopeAfterDeleteHook)
	if err = o.doAfterDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterDeleteHook function to empty object, but got: %#v", o)
	}
	tokensScopeAfterDeleteHooks = []TokensScopeHook{}

	AddTokensScopeHook(boil.BeforeUpsertHook, tokensScopeBeforeUpsertHook)
	if err = o.doBeforeUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpsertHook function to empty object, but got: %#v", o)
	}
	tokensScopeBeforeUpsertHooks = []TokensScopeHook{}

	AddTokensScopeHook(boil.AfterUpsertHook, tokensScopeAfterUpsertHook)
	if err = o.doAfterUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpsertHook function to empty object, but got: %#v", o)
	}
	tokensScopeAfterUpsertHooks = []TokensScopeHook{}
}

func testTokensScopesInsert(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &TokensScope{}
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := TokensScopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testTokensScopesInsertWhitelist(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &TokensScope{}
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Whitelist(tokensScopeColumnsWithoutDefault...)); err != nil {
		t.Error(err)
	}

	count, err := TokensScopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testTokensScopesReload(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &TokensScope{}
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if err = o.Reload(ctx, tx); err != nil {
		t.Error(err)
	}
}

func testTokensScopesReloadAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &TokensScope{}
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := TokensScopeSlice{o}

	if err = slice.ReloadAll(ctx, tx); err != nil {
		t.Error(err)
	}
}

func testTokensScopesSelect(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &TokensScope{}
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := TokensScopes().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 1 {
		t.Error("want one record, got:", len(slice))
	}
}

var (
	tokensScopeDBTypes = map[string]string{`TokenID`: `varchar`, `ScopeID`: `varchar`}
	_                  = bytes.MinRead
)

func testTokensScopesUpdate(t *testing.T) {
	t.Parallel()

	if 0 == len(tokensScopePrimaryKeyColumns) {
		t.Skip("Skipping table with no primary key columns")
	}
	if len(tokensScopeAllColumns) == len(tokensScopePrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &TokensScope{}
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := TokensScopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopePrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	if rowsAff, err := o.Update(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only affect one row but affected", rowsAff)
	}
}

func testTokensScopesSliceUpdateAll(t *testing.T) {
	t.Parallel()

	if len(tokensScopeAllColumns) == len(tokensScopePrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &TokensScope{}
	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := TokensScopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, tokensScopeDBTypes, true, tokensScopePrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	// Remove Primary keys and unique columns from what we plan to update
	var fields []string
	if strmangle.StringSliceMatch(tokensScopeAllColumns, tokensScopePrimaryKeyColumns) {
		fields = tokensScopeAllColumns
	} else {
		fields = strmangle.SetComplement(
			tokensScopeAllColumns,
			tokensScopePrimaryKeyColumns,
		)
	}

	value := reflect.Indirect(reflect.ValueOf(o))
	typ := reflect.TypeOf(o).Elem()
	n := typ.NumField()

	updateMap := M{}
	for _, col := range fields {
		for i := 0; i < n; i++ {
			f := typ.Field(i)
			if f.Tag.Get("boil") == col {
				updateMap[col] = value.Field(i).Interface()
			}
		}
	}

	slice := TokensScopeSlice{o}
	if rowsAff, err := slice.UpdateAll(ctx, tx, updateMap); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("wanted one record updated but got", rowsAff)
	}
}

func testTokensScopesUpsert(t *testing.T) {
	t.Parallel()

	if len(tokensScopeAllColumns) == len(tokensScopePrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}
	if len(mySQLTokensScopeUniqueColumns) == 0 {
		t.Skip("Skipping table with no unique columns to conflict on")
	}

	seed := randomize.NewSeed()
	var err error
	// Attempt the INSERT side of an UPSERT
	o := TokensScope{}
	if err = randomize.Struct(seed, &o, tokensScopeDBTypes, false); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert TokensScope: %s", err)
	}

	count, err := TokensScopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}

	// Attempt the UPDATE side of an UPSERT
	if err = randomize.Struct(seed, &o, tokensScopeDBTypes, false, tokensScopePrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize TokensScope struct: %s", err)
	}

	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert TokensScope: %s", err)
	}

	count, err = TokensScopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}
}
