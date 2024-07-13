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

func testNamecards(t *testing.T) {
	t.Parallel()

	query := Namecards()

	if query.Query == nil {
		t.Error("expected a query, got nothing")
	}
}

func testNamecardsDelete(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Namecard{}
	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
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

	count, err := Namecards().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testNamecardsQueryDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Namecard{}
	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if rowsAff, err := Namecards().DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := Namecards().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testNamecardsSliceDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Namecard{}
	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := NamecardSlice{o}

	if rowsAff, err := slice.DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := Namecards().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testNamecardsExists(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Namecard{}
	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	e, err := NamecardExists(ctx, tx, o.StudentPrefix)
	if err != nil {
		t.Errorf("Unable to check if Namecard exists: %s", err)
	}
	if !e {
		t.Errorf("Expected NamecardExists to return true, but got false.")
	}
}

func testNamecardsFind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Namecard{}
	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	namecardFound, err := FindNamecard(ctx, tx, o.StudentPrefix)
	if err != nil {
		t.Error(err)
	}

	if namecardFound == nil {
		t.Error("want a record, got nil")
	}
}

func testNamecardsBind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Namecard{}
	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if err = Namecards().Bind(ctx, tx, o); err != nil {
		t.Error(err)
	}
}

func testNamecardsOne(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Namecard{}
	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if x, err := Namecards().One(ctx, tx); err != nil {
		t.Error(err)
	} else if x == nil {
		t.Error("expected to get a non nil record")
	}
}

func testNamecardsAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	namecardOne := &Namecard{}
	namecardTwo := &Namecard{}
	if err = randomize.Struct(seed, namecardOne, namecardDBTypes, false, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}
	if err = randomize.Struct(seed, namecardTwo, namecardDBTypes, false, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = namecardOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = namecardTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := Namecards().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 2 {
		t.Error("want 2 records, got:", len(slice))
	}
}

func testNamecardsCount(t *testing.T) {
	t.Parallel()

	var err error
	seed := randomize.NewSeed()
	namecardOne := &Namecard{}
	namecardTwo := &Namecard{}
	if err = randomize.Struct(seed, namecardOne, namecardDBTypes, false, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}
	if err = randomize.Struct(seed, namecardTwo, namecardDBTypes, false, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = namecardOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = namecardTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Namecards().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 2 {
		t.Error("want 2 records, got:", count)
	}
}

func namecardBeforeInsertHook(ctx context.Context, e boil.ContextExecutor, o *Namecard) error {
	*o = Namecard{}
	return nil
}

func namecardAfterInsertHook(ctx context.Context, e boil.ContextExecutor, o *Namecard) error {
	*o = Namecard{}
	return nil
}

func namecardAfterSelectHook(ctx context.Context, e boil.ContextExecutor, o *Namecard) error {
	*o = Namecard{}
	return nil
}

func namecardBeforeUpdateHook(ctx context.Context, e boil.ContextExecutor, o *Namecard) error {
	*o = Namecard{}
	return nil
}

func namecardAfterUpdateHook(ctx context.Context, e boil.ContextExecutor, o *Namecard) error {
	*o = Namecard{}
	return nil
}

func namecardBeforeDeleteHook(ctx context.Context, e boil.ContextExecutor, o *Namecard) error {
	*o = Namecard{}
	return nil
}

func namecardAfterDeleteHook(ctx context.Context, e boil.ContextExecutor, o *Namecard) error {
	*o = Namecard{}
	return nil
}

func namecardBeforeUpsertHook(ctx context.Context, e boil.ContextExecutor, o *Namecard) error {
	*o = Namecard{}
	return nil
}

func namecardAfterUpsertHook(ctx context.Context, e boil.ContextExecutor, o *Namecard) error {
	*o = Namecard{}
	return nil
}

func testNamecardsHooks(t *testing.T) {
	t.Parallel()

	var err error

	ctx := context.Background()
	empty := &Namecard{}
	o := &Namecard{}

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, o, namecardDBTypes, false); err != nil {
		t.Errorf("Unable to randomize Namecard object: %s", err)
	}

	AddNamecardHook(boil.BeforeInsertHook, namecardBeforeInsertHook)
	if err = o.doBeforeInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeInsertHook function to empty object, but got: %#v", o)
	}
	namecardBeforeInsertHooks = []NamecardHook{}

	AddNamecardHook(boil.AfterInsertHook, namecardAfterInsertHook)
	if err = o.doAfterInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterInsertHook function to empty object, but got: %#v", o)
	}
	namecardAfterInsertHooks = []NamecardHook{}

	AddNamecardHook(boil.AfterSelectHook, namecardAfterSelectHook)
	if err = o.doAfterSelectHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterSelectHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterSelectHook function to empty object, but got: %#v", o)
	}
	namecardAfterSelectHooks = []NamecardHook{}

	AddNamecardHook(boil.BeforeUpdateHook, namecardBeforeUpdateHook)
	if err = o.doBeforeUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpdateHook function to empty object, but got: %#v", o)
	}
	namecardBeforeUpdateHooks = []NamecardHook{}

	AddNamecardHook(boil.AfterUpdateHook, namecardAfterUpdateHook)
	if err = o.doAfterUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpdateHook function to empty object, but got: %#v", o)
	}
	namecardAfterUpdateHooks = []NamecardHook{}

	AddNamecardHook(boil.BeforeDeleteHook, namecardBeforeDeleteHook)
	if err = o.doBeforeDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeDeleteHook function to empty object, but got: %#v", o)
	}
	namecardBeforeDeleteHooks = []NamecardHook{}

	AddNamecardHook(boil.AfterDeleteHook, namecardAfterDeleteHook)
	if err = o.doAfterDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterDeleteHook function to empty object, but got: %#v", o)
	}
	namecardAfterDeleteHooks = []NamecardHook{}

	AddNamecardHook(boil.BeforeUpsertHook, namecardBeforeUpsertHook)
	if err = o.doBeforeUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpsertHook function to empty object, but got: %#v", o)
	}
	namecardBeforeUpsertHooks = []NamecardHook{}

	AddNamecardHook(boil.AfterUpsertHook, namecardAfterUpsertHook)
	if err = o.doAfterUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpsertHook function to empty object, but got: %#v", o)
	}
	namecardAfterUpsertHooks = []NamecardHook{}
}

func testNamecardsInsert(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Namecard{}
	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Namecards().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testNamecardsInsertWhitelist(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Namecard{}
	if err = randomize.Struct(seed, o, namecardDBTypes, true); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Whitelist(namecardColumnsWithoutDefault...)); err != nil {
		t.Error(err)
	}

	count, err := Namecards().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testNamecardsReload(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Namecard{}
	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
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

func testNamecardsReloadAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Namecard{}
	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := NamecardSlice{o}

	if err = slice.ReloadAll(ctx, tx); err != nil {
		t.Error(err)
	}
}

func testNamecardsSelect(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Namecard{}
	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := Namecards().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 1 {
		t.Error("want one record, got:", len(slice))
	}
}

var (
	namecardDBTypes = map[string]string{`StudentPrefix`: `varchar`, `Color`: `varchar`}
	_               = bytes.MinRead
)

func testNamecardsUpdate(t *testing.T) {
	t.Parallel()

	if 0 == len(namecardPrimaryKeyColumns) {
		t.Skip("Skipping table with no primary key columns")
	}
	if len(namecardAllColumns) == len(namecardPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &Namecard{}
	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Namecards().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	if rowsAff, err := o.Update(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only affect one row but affected", rowsAff)
	}
}

func testNamecardsSliceUpdateAll(t *testing.T) {
	t.Parallel()

	if len(namecardAllColumns) == len(namecardPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &Namecard{}
	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Namecards().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, namecardDBTypes, true, namecardPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	// Remove Primary keys and unique columns from what we plan to update
	var fields []string
	if strmangle.StringSliceMatch(namecardAllColumns, namecardPrimaryKeyColumns) {
		fields = namecardAllColumns
	} else {
		fields = strmangle.SetComplement(
			namecardAllColumns,
			namecardPrimaryKeyColumns,
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

	slice := NamecardSlice{o}
	if rowsAff, err := slice.UpdateAll(ctx, tx, updateMap); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("wanted one record updated but got", rowsAff)
	}
}

func testNamecardsUpsert(t *testing.T) {
	t.Parallel()

	if len(namecardAllColumns) == len(namecardPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}
	if len(mySQLNamecardUniqueColumns) == 0 {
		t.Skip("Skipping table with no unique columns to conflict on")
	}

	seed := randomize.NewSeed()
	var err error
	// Attempt the INSERT side of an UPSERT
	o := Namecard{}
	if err = randomize.Struct(seed, &o, namecardDBTypes, false); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert Namecard: %s", err)
	}

	count, err := Namecards().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}

	// Attempt the UPDATE side of an UPSERT
	if err = randomize.Struct(seed, &o, namecardDBTypes, false, namecardPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Namecard struct: %s", err)
	}

	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert Namecard: %s", err)
	}

	count, err = Namecards().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}
}