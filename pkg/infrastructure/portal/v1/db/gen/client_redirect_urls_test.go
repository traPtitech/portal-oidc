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

func testClientRedirectUrls(t *testing.T) {
	t.Parallel()

	query := ClientRedirectUrls()

	if query.Query == nil {
		t.Error("expected a query, got nothing")
	}
}

func testClientRedirectUrlsDelete(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &ClientRedirectURL{}
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
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

	count, err := ClientRedirectUrls().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testClientRedirectUrlsQueryDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &ClientRedirectURL{}
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if rowsAff, err := ClientRedirectUrls().DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := ClientRedirectUrls().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testClientRedirectUrlsSliceDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &ClientRedirectURL{}
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := ClientRedirectURLSlice{o}

	if rowsAff, err := slice.DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := ClientRedirectUrls().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testClientRedirectUrlsExists(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &ClientRedirectURL{}
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	e, err := ClientRedirectURLExists(ctx, tx, o.ClientID, o.URL)
	if err != nil {
		t.Errorf("Unable to check if ClientRedirectURL exists: %s", err)
	}
	if !e {
		t.Errorf("Expected ClientRedirectURLExists to return true, but got false.")
	}
}

func testClientRedirectUrlsFind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &ClientRedirectURL{}
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	clientRedirectURLFound, err := FindClientRedirectURL(ctx, tx, o.ClientID, o.URL)
	if err != nil {
		t.Error(err)
	}

	if clientRedirectURLFound == nil {
		t.Error("want a record, got nil")
	}
}

func testClientRedirectUrlsBind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &ClientRedirectURL{}
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if err = ClientRedirectUrls().Bind(ctx, tx, o); err != nil {
		t.Error(err)
	}
}

func testClientRedirectUrlsOne(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &ClientRedirectURL{}
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if x, err := ClientRedirectUrls().One(ctx, tx); err != nil {
		t.Error(err)
	} else if x == nil {
		t.Error("expected to get a non nil record")
	}
}

func testClientRedirectUrlsAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	clientRedirectURLOne := &ClientRedirectURL{}
	clientRedirectURLTwo := &ClientRedirectURL{}
	if err = randomize.Struct(seed, clientRedirectURLOne, clientRedirectURLDBTypes, false, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}
	if err = randomize.Struct(seed, clientRedirectURLTwo, clientRedirectURLDBTypes, false, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = clientRedirectURLOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = clientRedirectURLTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := ClientRedirectUrls().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 2 {
		t.Error("want 2 records, got:", len(slice))
	}
}

func testClientRedirectUrlsCount(t *testing.T) {
	t.Parallel()

	var err error
	seed := randomize.NewSeed()
	clientRedirectURLOne := &ClientRedirectURL{}
	clientRedirectURLTwo := &ClientRedirectURL{}
	if err = randomize.Struct(seed, clientRedirectURLOne, clientRedirectURLDBTypes, false, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}
	if err = randomize.Struct(seed, clientRedirectURLTwo, clientRedirectURLDBTypes, false, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = clientRedirectURLOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = clientRedirectURLTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := ClientRedirectUrls().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 2 {
		t.Error("want 2 records, got:", count)
	}
}

func clientRedirectURLBeforeInsertHook(ctx context.Context, e boil.ContextExecutor, o *ClientRedirectURL) error {
	*o = ClientRedirectURL{}
	return nil
}

func clientRedirectURLAfterInsertHook(ctx context.Context, e boil.ContextExecutor, o *ClientRedirectURL) error {
	*o = ClientRedirectURL{}
	return nil
}

func clientRedirectURLAfterSelectHook(ctx context.Context, e boil.ContextExecutor, o *ClientRedirectURL) error {
	*o = ClientRedirectURL{}
	return nil
}

func clientRedirectURLBeforeUpdateHook(ctx context.Context, e boil.ContextExecutor, o *ClientRedirectURL) error {
	*o = ClientRedirectURL{}
	return nil
}

func clientRedirectURLAfterUpdateHook(ctx context.Context, e boil.ContextExecutor, o *ClientRedirectURL) error {
	*o = ClientRedirectURL{}
	return nil
}

func clientRedirectURLBeforeDeleteHook(ctx context.Context, e boil.ContextExecutor, o *ClientRedirectURL) error {
	*o = ClientRedirectURL{}
	return nil
}

func clientRedirectURLAfterDeleteHook(ctx context.Context, e boil.ContextExecutor, o *ClientRedirectURL) error {
	*o = ClientRedirectURL{}
	return nil
}

func clientRedirectURLBeforeUpsertHook(ctx context.Context, e boil.ContextExecutor, o *ClientRedirectURL) error {
	*o = ClientRedirectURL{}
	return nil
}

func clientRedirectURLAfterUpsertHook(ctx context.Context, e boil.ContextExecutor, o *ClientRedirectURL) error {
	*o = ClientRedirectURL{}
	return nil
}

func testClientRedirectUrlsHooks(t *testing.T) {
	t.Parallel()

	var err error

	ctx := context.Background()
	empty := &ClientRedirectURL{}
	o := &ClientRedirectURL{}

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, false); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL object: %s", err)
	}

	AddClientRedirectURLHook(boil.BeforeInsertHook, clientRedirectURLBeforeInsertHook)
	if err = o.doBeforeInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeInsertHook function to empty object, but got: %#v", o)
	}
	clientRedirectURLBeforeInsertHooks = []ClientRedirectURLHook{}

	AddClientRedirectURLHook(boil.AfterInsertHook, clientRedirectURLAfterInsertHook)
	if err = o.doAfterInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterInsertHook function to empty object, but got: %#v", o)
	}
	clientRedirectURLAfterInsertHooks = []ClientRedirectURLHook{}

	AddClientRedirectURLHook(boil.AfterSelectHook, clientRedirectURLAfterSelectHook)
	if err = o.doAfterSelectHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterSelectHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterSelectHook function to empty object, but got: %#v", o)
	}
	clientRedirectURLAfterSelectHooks = []ClientRedirectURLHook{}

	AddClientRedirectURLHook(boil.BeforeUpdateHook, clientRedirectURLBeforeUpdateHook)
	if err = o.doBeforeUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpdateHook function to empty object, but got: %#v", o)
	}
	clientRedirectURLBeforeUpdateHooks = []ClientRedirectURLHook{}

	AddClientRedirectURLHook(boil.AfterUpdateHook, clientRedirectURLAfterUpdateHook)
	if err = o.doAfterUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpdateHook function to empty object, but got: %#v", o)
	}
	clientRedirectURLAfterUpdateHooks = []ClientRedirectURLHook{}

	AddClientRedirectURLHook(boil.BeforeDeleteHook, clientRedirectURLBeforeDeleteHook)
	if err = o.doBeforeDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeDeleteHook function to empty object, but got: %#v", o)
	}
	clientRedirectURLBeforeDeleteHooks = []ClientRedirectURLHook{}

	AddClientRedirectURLHook(boil.AfterDeleteHook, clientRedirectURLAfterDeleteHook)
	if err = o.doAfterDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterDeleteHook function to empty object, but got: %#v", o)
	}
	clientRedirectURLAfterDeleteHooks = []ClientRedirectURLHook{}

	AddClientRedirectURLHook(boil.BeforeUpsertHook, clientRedirectURLBeforeUpsertHook)
	if err = o.doBeforeUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpsertHook function to empty object, but got: %#v", o)
	}
	clientRedirectURLBeforeUpsertHooks = []ClientRedirectURLHook{}

	AddClientRedirectURLHook(boil.AfterUpsertHook, clientRedirectURLAfterUpsertHook)
	if err = o.doAfterUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpsertHook function to empty object, but got: %#v", o)
	}
	clientRedirectURLAfterUpsertHooks = []ClientRedirectURLHook{}
}

func testClientRedirectUrlsInsert(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &ClientRedirectURL{}
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := ClientRedirectUrls().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testClientRedirectUrlsInsertWhitelist(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &ClientRedirectURL{}
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Whitelist(clientRedirectURLColumnsWithoutDefault...)); err != nil {
		t.Error(err)
	}

	count, err := ClientRedirectUrls().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testClientRedirectUrlsReload(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &ClientRedirectURL{}
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
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

func testClientRedirectUrlsReloadAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &ClientRedirectURL{}
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := ClientRedirectURLSlice{o}

	if err = slice.ReloadAll(ctx, tx); err != nil {
		t.Error(err)
	}
}

func testClientRedirectUrlsSelect(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &ClientRedirectURL{}
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := ClientRedirectUrls().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 1 {
		t.Error("want one record, got:", len(slice))
	}
}

var (
	clientRedirectURLDBTypes = map[string]string{`ClientID`: `varchar`, `URL`: `varchar`}
	_                        = bytes.MinRead
)

func testClientRedirectUrlsUpdate(t *testing.T) {
	t.Parallel()

	if 0 == len(clientRedirectURLPrimaryKeyColumns) {
		t.Skip("Skipping table with no primary key columns")
	}
	if len(clientRedirectURLAllColumns) == len(clientRedirectURLPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &ClientRedirectURL{}
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := ClientRedirectUrls().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	if rowsAff, err := o.Update(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only affect one row but affected", rowsAff)
	}
}

func testClientRedirectUrlsSliceUpdateAll(t *testing.T) {
	t.Parallel()

	if len(clientRedirectURLAllColumns) == len(clientRedirectURLPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &ClientRedirectURL{}
	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := ClientRedirectUrls().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, clientRedirectURLDBTypes, true, clientRedirectURLPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	// Remove Primary keys and unique columns from what we plan to update
	var fields []string
	if strmangle.StringSliceMatch(clientRedirectURLAllColumns, clientRedirectURLPrimaryKeyColumns) {
		fields = clientRedirectURLAllColumns
	} else {
		fields = strmangle.SetComplement(
			clientRedirectURLAllColumns,
			clientRedirectURLPrimaryKeyColumns,
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

	slice := ClientRedirectURLSlice{o}
	if rowsAff, err := slice.UpdateAll(ctx, tx, updateMap); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("wanted one record updated but got", rowsAff)
	}
}

func testClientRedirectUrlsUpsert(t *testing.T) {
	t.Parallel()

	if len(clientRedirectURLAllColumns) == len(clientRedirectURLPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}
	if len(mySQLClientRedirectURLUniqueColumns) == 0 {
		t.Skip("Skipping table with no unique columns to conflict on")
	}

	seed := randomize.NewSeed()
	var err error
	// Attempt the INSERT side of an UPSERT
	o := ClientRedirectURL{}
	if err = randomize.Struct(seed, &o, clientRedirectURLDBTypes, false); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert ClientRedirectURL: %s", err)
	}

	count, err := ClientRedirectUrls().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}

	// Attempt the UPDATE side of an UPSERT
	if err = randomize.Struct(seed, &o, clientRedirectURLDBTypes, false, clientRedirectURLPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize ClientRedirectURL struct: %s", err)
	}

	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert ClientRedirectURL: %s", err)
	}

	count, err = ClientRedirectUrls().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}
}
