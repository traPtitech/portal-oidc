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

func testScopes(t *testing.T) {
	t.Parallel()

	query := Scopes()

	if query.Query == nil {
		t.Error("expected a query, got nothing")
	}
}

func testScopesDelete(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Scope{}
	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
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

	count, err := Scopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testScopesQueryDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Scope{}
	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if rowsAff, err := Scopes().DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := Scopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testScopesSliceDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Scope{}
	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := ScopeSlice{o}

	if rowsAff, err := slice.DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := Scopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testScopesExists(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Scope{}
	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	e, err := ScopeExists(ctx, tx, o.ID)
	if err != nil {
		t.Errorf("Unable to check if Scope exists: %s", err)
	}
	if !e {
		t.Errorf("Expected ScopeExists to return true, but got false.")
	}
}

func testScopesFind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Scope{}
	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	scopeFound, err := FindScope(ctx, tx, o.ID)
	if err != nil {
		t.Error(err)
	}

	if scopeFound == nil {
		t.Error("want a record, got nil")
	}
}

func testScopesBind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Scope{}
	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if err = Scopes().Bind(ctx, tx, o); err != nil {
		t.Error(err)
	}
}

func testScopesOne(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Scope{}
	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if x, err := Scopes().One(ctx, tx); err != nil {
		t.Error(err)
	} else if x == nil {
		t.Error("expected to get a non nil record")
	}
}

func testScopesAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	scopeOne := &Scope{}
	scopeTwo := &Scope{}
	if err = randomize.Struct(seed, scopeOne, scopeDBTypes, false, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}
	if err = randomize.Struct(seed, scopeTwo, scopeDBTypes, false, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = scopeOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = scopeTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := Scopes().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 2 {
		t.Error("want 2 records, got:", len(slice))
	}
}

func testScopesCount(t *testing.T) {
	t.Parallel()

	var err error
	seed := randomize.NewSeed()
	scopeOne := &Scope{}
	scopeTwo := &Scope{}
	if err = randomize.Struct(seed, scopeOne, scopeDBTypes, false, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}
	if err = randomize.Struct(seed, scopeTwo, scopeDBTypes, false, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = scopeOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = scopeTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Scopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 2 {
		t.Error("want 2 records, got:", count)
	}
}

func scopeBeforeInsertHook(ctx context.Context, e boil.ContextExecutor, o *Scope) error {
	*o = Scope{}
	return nil
}

func scopeAfterInsertHook(ctx context.Context, e boil.ContextExecutor, o *Scope) error {
	*o = Scope{}
	return nil
}

func scopeAfterSelectHook(ctx context.Context, e boil.ContextExecutor, o *Scope) error {
	*o = Scope{}
	return nil
}

func scopeBeforeUpdateHook(ctx context.Context, e boil.ContextExecutor, o *Scope) error {
	*o = Scope{}
	return nil
}

func scopeAfterUpdateHook(ctx context.Context, e boil.ContextExecutor, o *Scope) error {
	*o = Scope{}
	return nil
}

func scopeBeforeDeleteHook(ctx context.Context, e boil.ContextExecutor, o *Scope) error {
	*o = Scope{}
	return nil
}

func scopeAfterDeleteHook(ctx context.Context, e boil.ContextExecutor, o *Scope) error {
	*o = Scope{}
	return nil
}

func scopeBeforeUpsertHook(ctx context.Context, e boil.ContextExecutor, o *Scope) error {
	*o = Scope{}
	return nil
}

func scopeAfterUpsertHook(ctx context.Context, e boil.ContextExecutor, o *Scope) error {
	*o = Scope{}
	return nil
}

func testScopesHooks(t *testing.T) {
	t.Parallel()

	var err error

	ctx := context.Background()
	empty := &Scope{}
	o := &Scope{}

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, o, scopeDBTypes, false); err != nil {
		t.Errorf("Unable to randomize Scope object: %s", err)
	}

	AddScopeHook(boil.BeforeInsertHook, scopeBeforeInsertHook)
	if err = o.doBeforeInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeInsertHook function to empty object, but got: %#v", o)
	}
	scopeBeforeInsertHooks = []ScopeHook{}

	AddScopeHook(boil.AfterInsertHook, scopeAfterInsertHook)
	if err = o.doAfterInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterInsertHook function to empty object, but got: %#v", o)
	}
	scopeAfterInsertHooks = []ScopeHook{}

	AddScopeHook(boil.AfterSelectHook, scopeAfterSelectHook)
	if err = o.doAfterSelectHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterSelectHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterSelectHook function to empty object, but got: %#v", o)
	}
	scopeAfterSelectHooks = []ScopeHook{}

	AddScopeHook(boil.BeforeUpdateHook, scopeBeforeUpdateHook)
	if err = o.doBeforeUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpdateHook function to empty object, but got: %#v", o)
	}
	scopeBeforeUpdateHooks = []ScopeHook{}

	AddScopeHook(boil.AfterUpdateHook, scopeAfterUpdateHook)
	if err = o.doAfterUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpdateHook function to empty object, but got: %#v", o)
	}
	scopeAfterUpdateHooks = []ScopeHook{}

	AddScopeHook(boil.BeforeDeleteHook, scopeBeforeDeleteHook)
	if err = o.doBeforeDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeDeleteHook function to empty object, but got: %#v", o)
	}
	scopeBeforeDeleteHooks = []ScopeHook{}

	AddScopeHook(boil.AfterDeleteHook, scopeAfterDeleteHook)
	if err = o.doAfterDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterDeleteHook function to empty object, but got: %#v", o)
	}
	scopeAfterDeleteHooks = []ScopeHook{}

	AddScopeHook(boil.BeforeUpsertHook, scopeBeforeUpsertHook)
	if err = o.doBeforeUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpsertHook function to empty object, but got: %#v", o)
	}
	scopeBeforeUpsertHooks = []ScopeHook{}

	AddScopeHook(boil.AfterUpsertHook, scopeAfterUpsertHook)
	if err = o.doAfterUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpsertHook function to empty object, but got: %#v", o)
	}
	scopeAfterUpsertHooks = []ScopeHook{}
}

func testScopesInsert(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Scope{}
	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Scopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testScopesInsertWhitelist(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Scope{}
	if err = randomize.Struct(seed, o, scopeDBTypes, true); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Whitelist(scopeColumnsWithoutDefault...)); err != nil {
		t.Error(err)
	}

	count, err := Scopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testScopesReload(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Scope{}
	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
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

func testScopesReloadAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Scope{}
	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := ScopeSlice{o}

	if err = slice.ReloadAll(ctx, tx); err != nil {
		t.Error(err)
	}
}

func testScopesSelect(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Scope{}
	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := Scopes().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 1 {
		t.Error("want one record, got:", len(slice))
	}
}

var (
	scopeDBTypes = map[string]string{`ID`: `varchar`, `Name`: `tinytext`, `Description`: `text`, `Warning`: `tinyint`}
	_            = bytes.MinRead
)

func testScopesUpdate(t *testing.T) {
	t.Parallel()

	if 0 == len(scopePrimaryKeyColumns) {
		t.Skip("Skipping table with no primary key columns")
	}
	if len(scopeAllColumns) == len(scopePrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &Scope{}
	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Scopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopePrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	if rowsAff, err := o.Update(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only affect one row but affected", rowsAff)
	}
}

func testScopesSliceUpdateAll(t *testing.T) {
	t.Parallel()

	if len(scopeAllColumns) == len(scopePrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &Scope{}
	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Scopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, scopeDBTypes, true, scopePrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	// Remove Primary keys and unique columns from what we plan to update
	var fields []string
	if strmangle.StringSliceMatch(scopeAllColumns, scopePrimaryKeyColumns) {
		fields = scopeAllColumns
	} else {
		fields = strmangle.SetComplement(
			scopeAllColumns,
			scopePrimaryKeyColumns,
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

	slice := ScopeSlice{o}
	if rowsAff, err := slice.UpdateAll(ctx, tx, updateMap); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("wanted one record updated but got", rowsAff)
	}
}

func testScopesUpsert(t *testing.T) {
	t.Parallel()

	if len(scopeAllColumns) == len(scopePrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}
	if len(mySQLScopeUniqueColumns) == 0 {
		t.Skip("Skipping table with no unique columns to conflict on")
	}

	seed := randomize.NewSeed()
	var err error
	// Attempt the INSERT side of an UPSERT
	o := Scope{}
	if err = randomize.Struct(seed, &o, scopeDBTypes, false); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert Scope: %s", err)
	}

	count, err := Scopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}

	// Attempt the UPDATE side of an UPSERT
	if err = randomize.Struct(seed, &o, scopeDBTypes, false, scopePrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Scope struct: %s", err)
	}

	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert Scope: %s", err)
	}

	count, err = Scopes().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}
}
