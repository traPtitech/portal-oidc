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

func testMails(t *testing.T) {
	t.Parallel()

	query := Mails()

	if query.Query == nil {
		t.Error("expected a query, got nothing")
	}
}

func testMailsDelete(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Mail{}
	if err = randomize.Struct(seed, o, mailDBTypes, true, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
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

	count, err := Mails().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testMailsQueryDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Mail{}
	if err = randomize.Struct(seed, o, mailDBTypes, true, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if rowsAff, err := Mails().DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := Mails().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testMailsSliceDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Mail{}
	if err = randomize.Struct(seed, o, mailDBTypes, true, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := MailSlice{o}

	if rowsAff, err := slice.DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := Mails().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testMailsExists(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Mail{}
	if err = randomize.Struct(seed, o, mailDBTypes, true, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	e, err := MailExists(ctx, tx, o.ID)
	if err != nil {
		t.Errorf("Unable to check if Mail exists: %s", err)
	}
	if !e {
		t.Errorf("Expected MailExists to return true, but got false.")
	}
}

func testMailsFind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Mail{}
	if err = randomize.Struct(seed, o, mailDBTypes, true, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	mailFound, err := FindMail(ctx, tx, o.ID)
	if err != nil {
		t.Error(err)
	}

	if mailFound == nil {
		t.Error("want a record, got nil")
	}
}

func testMailsBind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Mail{}
	if err = randomize.Struct(seed, o, mailDBTypes, true, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if err = Mails().Bind(ctx, tx, o); err != nil {
		t.Error(err)
	}
}

func testMailsOne(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Mail{}
	if err = randomize.Struct(seed, o, mailDBTypes, true, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if x, err := Mails().One(ctx, tx); err != nil {
		t.Error(err)
	} else if x == nil {
		t.Error("expected to get a non nil record")
	}
}

func testMailsAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	mailOne := &Mail{}
	mailTwo := &Mail{}
	if err = randomize.Struct(seed, mailOne, mailDBTypes, false, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}
	if err = randomize.Struct(seed, mailTwo, mailDBTypes, false, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = mailOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = mailTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := Mails().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 2 {
		t.Error("want 2 records, got:", len(slice))
	}
}

func testMailsCount(t *testing.T) {
	t.Parallel()

	var err error
	seed := randomize.NewSeed()
	mailOne := &Mail{}
	mailTwo := &Mail{}
	if err = randomize.Struct(seed, mailOne, mailDBTypes, false, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}
	if err = randomize.Struct(seed, mailTwo, mailDBTypes, false, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = mailOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = mailTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Mails().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 2 {
		t.Error("want 2 records, got:", count)
	}
}

func mailBeforeInsertHook(ctx context.Context, e boil.ContextExecutor, o *Mail) error {
	*o = Mail{}
	return nil
}

func mailAfterInsertHook(ctx context.Context, e boil.ContextExecutor, o *Mail) error {
	*o = Mail{}
	return nil
}

func mailAfterSelectHook(ctx context.Context, e boil.ContextExecutor, o *Mail) error {
	*o = Mail{}
	return nil
}

func mailBeforeUpdateHook(ctx context.Context, e boil.ContextExecutor, o *Mail) error {
	*o = Mail{}
	return nil
}

func mailAfterUpdateHook(ctx context.Context, e boil.ContextExecutor, o *Mail) error {
	*o = Mail{}
	return nil
}

func mailBeforeDeleteHook(ctx context.Context, e boil.ContextExecutor, o *Mail) error {
	*o = Mail{}
	return nil
}

func mailAfterDeleteHook(ctx context.Context, e boil.ContextExecutor, o *Mail) error {
	*o = Mail{}
	return nil
}

func mailBeforeUpsertHook(ctx context.Context, e boil.ContextExecutor, o *Mail) error {
	*o = Mail{}
	return nil
}

func mailAfterUpsertHook(ctx context.Context, e boil.ContextExecutor, o *Mail) error {
	*o = Mail{}
	return nil
}

func testMailsHooks(t *testing.T) {
	t.Parallel()

	var err error

	ctx := context.Background()
	empty := &Mail{}
	o := &Mail{}

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, o, mailDBTypes, false); err != nil {
		t.Errorf("Unable to randomize Mail object: %s", err)
	}

	AddMailHook(boil.BeforeInsertHook, mailBeforeInsertHook)
	if err = o.doBeforeInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeInsertHook function to empty object, but got: %#v", o)
	}
	mailBeforeInsertHooks = []MailHook{}

	AddMailHook(boil.AfterInsertHook, mailAfterInsertHook)
	if err = o.doAfterInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterInsertHook function to empty object, but got: %#v", o)
	}
	mailAfterInsertHooks = []MailHook{}

	AddMailHook(boil.AfterSelectHook, mailAfterSelectHook)
	if err = o.doAfterSelectHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterSelectHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterSelectHook function to empty object, but got: %#v", o)
	}
	mailAfterSelectHooks = []MailHook{}

	AddMailHook(boil.BeforeUpdateHook, mailBeforeUpdateHook)
	if err = o.doBeforeUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpdateHook function to empty object, but got: %#v", o)
	}
	mailBeforeUpdateHooks = []MailHook{}

	AddMailHook(boil.AfterUpdateHook, mailAfterUpdateHook)
	if err = o.doAfterUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpdateHook function to empty object, but got: %#v", o)
	}
	mailAfterUpdateHooks = []MailHook{}

	AddMailHook(boil.BeforeDeleteHook, mailBeforeDeleteHook)
	if err = o.doBeforeDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeDeleteHook function to empty object, but got: %#v", o)
	}
	mailBeforeDeleteHooks = []MailHook{}

	AddMailHook(boil.AfterDeleteHook, mailAfterDeleteHook)
	if err = o.doAfterDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterDeleteHook function to empty object, but got: %#v", o)
	}
	mailAfterDeleteHooks = []MailHook{}

	AddMailHook(boil.BeforeUpsertHook, mailBeforeUpsertHook)
	if err = o.doBeforeUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpsertHook function to empty object, but got: %#v", o)
	}
	mailBeforeUpsertHooks = []MailHook{}

	AddMailHook(boil.AfterUpsertHook, mailAfterUpsertHook)
	if err = o.doAfterUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpsertHook function to empty object, but got: %#v", o)
	}
	mailAfterUpsertHooks = []MailHook{}
}

func testMailsInsert(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Mail{}
	if err = randomize.Struct(seed, o, mailDBTypes, true, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Mails().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testMailsInsertWhitelist(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Mail{}
	if err = randomize.Struct(seed, o, mailDBTypes, true); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Whitelist(mailColumnsWithoutDefault...)); err != nil {
		t.Error(err)
	}

	count, err := Mails().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testMailsReload(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Mail{}
	if err = randomize.Struct(seed, o, mailDBTypes, true, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
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

func testMailsReloadAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Mail{}
	if err = randomize.Struct(seed, o, mailDBTypes, true, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := MailSlice{o}

	if err = slice.ReloadAll(ctx, tx); err != nil {
		t.Error(err)
	}
}

func testMailsSelect(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Mail{}
	if err = randomize.Struct(seed, o, mailDBTypes, true, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := Mails().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 1 {
		t.Error("want one record, got:", len(slice))
	}
}

var (
	mailDBTypes = map[string]string{`ID`: `char`, `To`: `text`, `Sub`: `varchar`, `Main`: `text`, `OperatorID`: `varchar`, `CreatedAt`: `datetime`}
	_           = bytes.MinRead
)

func testMailsUpdate(t *testing.T) {
	t.Parallel()

	if 0 == len(mailPrimaryKeyColumns) {
		t.Skip("Skipping table with no primary key columns")
	}
	if len(mailAllColumns) == len(mailPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &Mail{}
	if err = randomize.Struct(seed, o, mailDBTypes, true, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Mails().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, mailDBTypes, true, mailPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	if rowsAff, err := o.Update(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only affect one row but affected", rowsAff)
	}
}

func testMailsSliceUpdateAll(t *testing.T) {
	t.Parallel()

	if len(mailAllColumns) == len(mailPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &Mail{}
	if err = randomize.Struct(seed, o, mailDBTypes, true, mailColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Mails().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, mailDBTypes, true, mailPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	// Remove Primary keys and unique columns from what we plan to update
	var fields []string
	if strmangle.StringSliceMatch(mailAllColumns, mailPrimaryKeyColumns) {
		fields = mailAllColumns
	} else {
		fields = strmangle.SetComplement(
			mailAllColumns,
			mailPrimaryKeyColumns,
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

	slice := MailSlice{o}
	if rowsAff, err := slice.UpdateAll(ctx, tx, updateMap); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("wanted one record updated but got", rowsAff)
	}
}

func testMailsUpsert(t *testing.T) {
	t.Parallel()

	if len(mailAllColumns) == len(mailPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}
	if len(mySQLMailUniqueColumns) == 0 {
		t.Skip("Skipping table with no unique columns to conflict on")
	}

	seed := randomize.NewSeed()
	var err error
	// Attempt the INSERT side of an UPSERT
	o := Mail{}
	if err = randomize.Struct(seed, &o, mailDBTypes, false); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert Mail: %s", err)
	}

	count, err := Mails().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}

	// Attempt the UPDATE side of an UPSERT
	if err = randomize.Struct(seed, &o, mailDBTypes, false, mailPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Mail struct: %s", err)
	}

	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert Mail: %s", err)
	}

	count, err = Mails().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}
}
