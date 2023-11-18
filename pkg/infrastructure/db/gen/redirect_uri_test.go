// Code generated by SQLBoiler 4.15.0 (https://github.com/volatiletech/sqlboiler). DO NOT EDIT.
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

func testRedirectUris(t *testing.T) {
	t.Parallel()

	query := RedirectUris()

	if query.Query == nil {
		t.Error("expected a query, got nothing")
	}
}

func testRedirectUrisDelete(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RedirectURI{}
	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
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

	count, err := RedirectUris().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testRedirectUrisQueryDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RedirectURI{}
	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if rowsAff, err := RedirectUris().DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := RedirectUris().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testRedirectUrisSliceDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RedirectURI{}
	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := RedirectURISlice{o}

	if rowsAff, err := slice.DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := RedirectUris().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testRedirectUrisExists(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RedirectURI{}
	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	e, err := RedirectURIExists(ctx, tx, o.ID)
	if err != nil {
		t.Errorf("Unable to check if RedirectURI exists: %s", err)
	}
	if !e {
		t.Errorf("Expected RedirectURIExists to return true, but got false.")
	}
}

func testRedirectUrisFind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RedirectURI{}
	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	redirectURIFound, err := FindRedirectURI(ctx, tx, o.ID)
	if err != nil {
		t.Error(err)
	}

	if redirectURIFound == nil {
		t.Error("want a record, got nil")
	}
}

func testRedirectUrisBind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RedirectURI{}
	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if err = RedirectUris().Bind(ctx, tx, o); err != nil {
		t.Error(err)
	}
}

func testRedirectUrisOne(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RedirectURI{}
	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if x, err := RedirectUris().One(ctx, tx); err != nil {
		t.Error(err)
	} else if x == nil {
		t.Error("expected to get a non nil record")
	}
}

func testRedirectUrisAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	redirectURIOne := &RedirectURI{}
	redirectURITwo := &RedirectURI{}
	if err = randomize.Struct(seed, redirectURIOne, redirectURIDBTypes, false, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}
	if err = randomize.Struct(seed, redirectURITwo, redirectURIDBTypes, false, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = redirectURIOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = redirectURITwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := RedirectUris().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 2 {
		t.Error("want 2 records, got:", len(slice))
	}
}

func testRedirectUrisCount(t *testing.T) {
	t.Parallel()

	var err error
	seed := randomize.NewSeed()
	redirectURIOne := &RedirectURI{}
	redirectURITwo := &RedirectURI{}
	if err = randomize.Struct(seed, redirectURIOne, redirectURIDBTypes, false, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}
	if err = randomize.Struct(seed, redirectURITwo, redirectURIDBTypes, false, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = redirectURIOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = redirectURITwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := RedirectUris().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 2 {
		t.Error("want 2 records, got:", count)
	}
}

func redirectURIBeforeInsertHook(ctx context.Context, e boil.ContextExecutor, o *RedirectURI) error {
	*o = RedirectURI{}
	return nil
}

func redirectURIAfterInsertHook(ctx context.Context, e boil.ContextExecutor, o *RedirectURI) error {
	*o = RedirectURI{}
	return nil
}

func redirectURIAfterSelectHook(ctx context.Context, e boil.ContextExecutor, o *RedirectURI) error {
	*o = RedirectURI{}
	return nil
}

func redirectURIBeforeUpdateHook(ctx context.Context, e boil.ContextExecutor, o *RedirectURI) error {
	*o = RedirectURI{}
	return nil
}

func redirectURIAfterUpdateHook(ctx context.Context, e boil.ContextExecutor, o *RedirectURI) error {
	*o = RedirectURI{}
	return nil
}

func redirectURIBeforeDeleteHook(ctx context.Context, e boil.ContextExecutor, o *RedirectURI) error {
	*o = RedirectURI{}
	return nil
}

func redirectURIAfterDeleteHook(ctx context.Context, e boil.ContextExecutor, o *RedirectURI) error {
	*o = RedirectURI{}
	return nil
}

func redirectURIBeforeUpsertHook(ctx context.Context, e boil.ContextExecutor, o *RedirectURI) error {
	*o = RedirectURI{}
	return nil
}

func redirectURIAfterUpsertHook(ctx context.Context, e boil.ContextExecutor, o *RedirectURI) error {
	*o = RedirectURI{}
	return nil
}

func testRedirectUrisHooks(t *testing.T) {
	t.Parallel()

	var err error

	ctx := context.Background()
	empty := &RedirectURI{}
	o := &RedirectURI{}

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, o, redirectURIDBTypes, false); err != nil {
		t.Errorf("Unable to randomize RedirectURI object: %s", err)
	}

	AddRedirectURIHook(boil.BeforeInsertHook, redirectURIBeforeInsertHook)
	if err = o.doBeforeInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeInsertHook function to empty object, but got: %#v", o)
	}
	redirectURIBeforeInsertHooks = []RedirectURIHook{}

	AddRedirectURIHook(boil.AfterInsertHook, redirectURIAfterInsertHook)
	if err = o.doAfterInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterInsertHook function to empty object, but got: %#v", o)
	}
	redirectURIAfterInsertHooks = []RedirectURIHook{}

	AddRedirectURIHook(boil.AfterSelectHook, redirectURIAfterSelectHook)
	if err = o.doAfterSelectHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterSelectHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterSelectHook function to empty object, but got: %#v", o)
	}
	redirectURIAfterSelectHooks = []RedirectURIHook{}

	AddRedirectURIHook(boil.BeforeUpdateHook, redirectURIBeforeUpdateHook)
	if err = o.doBeforeUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpdateHook function to empty object, but got: %#v", o)
	}
	redirectURIBeforeUpdateHooks = []RedirectURIHook{}

	AddRedirectURIHook(boil.AfterUpdateHook, redirectURIAfterUpdateHook)
	if err = o.doAfterUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpdateHook function to empty object, but got: %#v", o)
	}
	redirectURIAfterUpdateHooks = []RedirectURIHook{}

	AddRedirectURIHook(boil.BeforeDeleteHook, redirectURIBeforeDeleteHook)
	if err = o.doBeforeDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeDeleteHook function to empty object, but got: %#v", o)
	}
	redirectURIBeforeDeleteHooks = []RedirectURIHook{}

	AddRedirectURIHook(boil.AfterDeleteHook, redirectURIAfterDeleteHook)
	if err = o.doAfterDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterDeleteHook function to empty object, but got: %#v", o)
	}
	redirectURIAfterDeleteHooks = []RedirectURIHook{}

	AddRedirectURIHook(boil.BeforeUpsertHook, redirectURIBeforeUpsertHook)
	if err = o.doBeforeUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpsertHook function to empty object, but got: %#v", o)
	}
	redirectURIBeforeUpsertHooks = []RedirectURIHook{}

	AddRedirectURIHook(boil.AfterUpsertHook, redirectURIAfterUpsertHook)
	if err = o.doAfterUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpsertHook function to empty object, but got: %#v", o)
	}
	redirectURIAfterUpsertHooks = []RedirectURIHook{}
}

func testRedirectUrisInsert(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RedirectURI{}
	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := RedirectUris().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testRedirectUrisInsertWhitelist(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RedirectURI{}
	if err = randomize.Struct(seed, o, redirectURIDBTypes, true); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Whitelist(redirectURIColumnsWithoutDefault...)); err != nil {
		t.Error(err)
	}

	count, err := RedirectUris().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testRedirectURIToOneClientUsingClient(t *testing.T) {
	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()

	var local RedirectURI
	var foreign Client

	seed := randomize.NewSeed()
	if err := randomize.Struct(seed, &local, redirectURIDBTypes, false, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}
	if err := randomize.Struct(seed, &foreign, clientDBTypes, false, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	if err := foreign.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	local.ClientID = foreign.ID
	if err := local.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	check, err := local.Client().One(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}

	if check.ID != foreign.ID {
		t.Errorf("want: %v, got %v", foreign.ID, check.ID)
	}

	ranAfterSelectHook := false
	AddClientHook(boil.AfterSelectHook, func(ctx context.Context, e boil.ContextExecutor, o *Client) error {
		ranAfterSelectHook = true
		return nil
	})

	slice := RedirectURISlice{&local}
	if err = local.L.LoadClient(ctx, tx, false, (*[]*RedirectURI)(&slice), nil); err != nil {
		t.Fatal(err)
	}
	if local.R.Client == nil {
		t.Error("struct should have been eager loaded")
	}

	local.R.Client = nil
	if err = local.L.LoadClient(ctx, tx, true, &local, nil); err != nil {
		t.Fatal(err)
	}
	if local.R.Client == nil {
		t.Error("struct should have been eager loaded")
	}

	if !ranAfterSelectHook {
		t.Error("failed to run AfterSelect hook for relationship")
	}
}

func testRedirectURIToOneSetOpClientUsingClient(t *testing.T) {
	var err error

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()

	var a RedirectURI
	var b, c Client

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, &a, redirectURIDBTypes, false, strmangle.SetComplement(redirectURIPrimaryKeyColumns, redirectURIColumnsWithoutDefault)...); err != nil {
		t.Fatal(err)
	}
	if err = randomize.Struct(seed, &b, clientDBTypes, false, strmangle.SetComplement(clientPrimaryKeyColumns, clientColumnsWithoutDefault)...); err != nil {
		t.Fatal(err)
	}
	if err = randomize.Struct(seed, &c, clientDBTypes, false, strmangle.SetComplement(clientPrimaryKeyColumns, clientColumnsWithoutDefault)...); err != nil {
		t.Fatal(err)
	}

	if err := a.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}
	if err = b.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	for i, x := range []*Client{&b, &c} {
		err = a.SetClient(ctx, tx, i != 0, x)
		if err != nil {
			t.Fatal(err)
		}

		if a.R.Client != x {
			t.Error("relationship struct not set to correct value")
		}

		if x.R.RedirectUris[0] != &a {
			t.Error("failed to append to foreign relationship struct")
		}
		if a.ClientID != x.ID {
			t.Error("foreign key was wrong value", a.ClientID)
		}

		zero := reflect.Zero(reflect.TypeOf(a.ClientID))
		reflect.Indirect(reflect.ValueOf(&a.ClientID)).Set(zero)

		if err = a.Reload(ctx, tx); err != nil {
			t.Fatal("failed to reload", err)
		}

		if a.ClientID != x.ID {
			t.Error("foreign key was wrong value", a.ClientID, x.ID)
		}
	}
}

func testRedirectUrisReload(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RedirectURI{}
	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
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

func testRedirectUrisReloadAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RedirectURI{}
	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := RedirectURISlice{o}

	if err = slice.ReloadAll(ctx, tx); err != nil {
		t.Error(err)
	}
}

func testRedirectUrisSelect(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RedirectURI{}
	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := RedirectUris().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 1 {
		t.Error("want one record, got:", len(slice))
	}
}

var (
	redirectURIDBTypes = map[string]string{`ID`: `char`, `ClientID`: `char`, `URI`: `text`, `CreatedAt`: `datetime`, `UpdatedAt`: `datetime`}
	_                  = bytes.MinRead
)

func testRedirectUrisUpdate(t *testing.T) {
	t.Parallel()

	if 0 == len(redirectURIPrimaryKeyColumns) {
		t.Skip("Skipping table with no primary key columns")
	}
	if len(redirectURIAllColumns) == len(redirectURIPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &RedirectURI{}
	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := RedirectUris().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	if rowsAff, err := o.Update(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only affect one row but affected", rowsAff)
	}
}

func testRedirectUrisSliceUpdateAll(t *testing.T) {
	t.Parallel()

	if len(redirectURIAllColumns) == len(redirectURIPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &RedirectURI{}
	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := RedirectUris().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, redirectURIDBTypes, true, redirectURIPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	// Remove Primary keys and unique columns from what we plan to update
	var fields []string
	if strmangle.StringSliceMatch(redirectURIAllColumns, redirectURIPrimaryKeyColumns) {
		fields = redirectURIAllColumns
	} else {
		fields = strmangle.SetComplement(
			redirectURIAllColumns,
			redirectURIPrimaryKeyColumns,
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

	slice := RedirectURISlice{o}
	if rowsAff, err := slice.UpdateAll(ctx, tx, updateMap); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("wanted one record updated but got", rowsAff)
	}
}

func testRedirectUrisUpsert(t *testing.T) {
	t.Parallel()

	if len(redirectURIAllColumns) == len(redirectURIPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}
	if len(mySQLRedirectURIUniqueColumns) == 0 {
		t.Skip("Skipping table with no unique columns to conflict on")
	}

	seed := randomize.NewSeed()
	var err error
	// Attempt the INSERT side of an UPSERT
	o := RedirectURI{}
	if err = randomize.Struct(seed, &o, redirectURIDBTypes, false); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert RedirectURI: %s", err)
	}

	count, err := RedirectUris().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}

	// Attempt the UPDATE side of an UPSERT
	if err = randomize.Struct(seed, &o, redirectURIDBTypes, false, redirectURIPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize RedirectURI struct: %s", err)
	}

	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert RedirectURI: %s", err)
	}

	count, err = RedirectUris().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}
}
