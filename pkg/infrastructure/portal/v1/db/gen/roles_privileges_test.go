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

func testRolesPrivileges(t *testing.T) {
	t.Parallel()

	query := RolesPrivileges()

	if query.Query == nil {
		t.Error("expected a query, got nothing")
	}
}

func testRolesPrivilegesDelete(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RolesPrivilege{}
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
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

	count, err := RolesPrivileges().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testRolesPrivilegesQueryDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RolesPrivilege{}
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if rowsAff, err := RolesPrivileges().DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := RolesPrivileges().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testRolesPrivilegesSliceDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RolesPrivilege{}
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := RolesPrivilegeSlice{o}

	if rowsAff, err := slice.DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := RolesPrivileges().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testRolesPrivilegesExists(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RolesPrivilege{}
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	e, err := RolesPrivilegeExists(ctx, tx, o.RoleID, o.PrivilegeID)
	if err != nil {
		t.Errorf("Unable to check if RolesPrivilege exists: %s", err)
	}
	if !e {
		t.Errorf("Expected RolesPrivilegeExists to return true, but got false.")
	}
}

func testRolesPrivilegesFind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RolesPrivilege{}
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	rolesPrivilegeFound, err := FindRolesPrivilege(ctx, tx, o.RoleID, o.PrivilegeID)
	if err != nil {
		t.Error(err)
	}

	if rolesPrivilegeFound == nil {
		t.Error("want a record, got nil")
	}
}

func testRolesPrivilegesBind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RolesPrivilege{}
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if err = RolesPrivileges().Bind(ctx, tx, o); err != nil {
		t.Error(err)
	}
}

func testRolesPrivilegesOne(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RolesPrivilege{}
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if x, err := RolesPrivileges().One(ctx, tx); err != nil {
		t.Error(err)
	} else if x == nil {
		t.Error("expected to get a non nil record")
	}
}

func testRolesPrivilegesAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	rolesPrivilegeOne := &RolesPrivilege{}
	rolesPrivilegeTwo := &RolesPrivilege{}
	if err = randomize.Struct(seed, rolesPrivilegeOne, rolesPrivilegeDBTypes, false, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}
	if err = randomize.Struct(seed, rolesPrivilegeTwo, rolesPrivilegeDBTypes, false, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = rolesPrivilegeOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = rolesPrivilegeTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := RolesPrivileges().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 2 {
		t.Error("want 2 records, got:", len(slice))
	}
}

func testRolesPrivilegesCount(t *testing.T) {
	t.Parallel()

	var err error
	seed := randomize.NewSeed()
	rolesPrivilegeOne := &RolesPrivilege{}
	rolesPrivilegeTwo := &RolesPrivilege{}
	if err = randomize.Struct(seed, rolesPrivilegeOne, rolesPrivilegeDBTypes, false, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}
	if err = randomize.Struct(seed, rolesPrivilegeTwo, rolesPrivilegeDBTypes, false, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = rolesPrivilegeOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = rolesPrivilegeTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := RolesPrivileges().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 2 {
		t.Error("want 2 records, got:", count)
	}
}

func rolesPrivilegeBeforeInsertHook(ctx context.Context, e boil.ContextExecutor, o *RolesPrivilege) error {
	*o = RolesPrivilege{}
	return nil
}

func rolesPrivilegeAfterInsertHook(ctx context.Context, e boil.ContextExecutor, o *RolesPrivilege) error {
	*o = RolesPrivilege{}
	return nil
}

func rolesPrivilegeAfterSelectHook(ctx context.Context, e boil.ContextExecutor, o *RolesPrivilege) error {
	*o = RolesPrivilege{}
	return nil
}

func rolesPrivilegeBeforeUpdateHook(ctx context.Context, e boil.ContextExecutor, o *RolesPrivilege) error {
	*o = RolesPrivilege{}
	return nil
}

func rolesPrivilegeAfterUpdateHook(ctx context.Context, e boil.ContextExecutor, o *RolesPrivilege) error {
	*o = RolesPrivilege{}
	return nil
}

func rolesPrivilegeBeforeDeleteHook(ctx context.Context, e boil.ContextExecutor, o *RolesPrivilege) error {
	*o = RolesPrivilege{}
	return nil
}

func rolesPrivilegeAfterDeleteHook(ctx context.Context, e boil.ContextExecutor, o *RolesPrivilege) error {
	*o = RolesPrivilege{}
	return nil
}

func rolesPrivilegeBeforeUpsertHook(ctx context.Context, e boil.ContextExecutor, o *RolesPrivilege) error {
	*o = RolesPrivilege{}
	return nil
}

func rolesPrivilegeAfterUpsertHook(ctx context.Context, e boil.ContextExecutor, o *RolesPrivilege) error {
	*o = RolesPrivilege{}
	return nil
}

func testRolesPrivilegesHooks(t *testing.T) {
	t.Parallel()

	var err error

	ctx := context.Background()
	empty := &RolesPrivilege{}
	o := &RolesPrivilege{}

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, false); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege object: %s", err)
	}

	AddRolesPrivilegeHook(boil.BeforeInsertHook, rolesPrivilegeBeforeInsertHook)
	if err = o.doBeforeInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeInsertHook function to empty object, but got: %#v", o)
	}
	rolesPrivilegeBeforeInsertHooks = []RolesPrivilegeHook{}

	AddRolesPrivilegeHook(boil.AfterInsertHook, rolesPrivilegeAfterInsertHook)
	if err = o.doAfterInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterInsertHook function to empty object, but got: %#v", o)
	}
	rolesPrivilegeAfterInsertHooks = []RolesPrivilegeHook{}

	AddRolesPrivilegeHook(boil.AfterSelectHook, rolesPrivilegeAfterSelectHook)
	if err = o.doAfterSelectHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterSelectHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterSelectHook function to empty object, but got: %#v", o)
	}
	rolesPrivilegeAfterSelectHooks = []RolesPrivilegeHook{}

	AddRolesPrivilegeHook(boil.BeforeUpdateHook, rolesPrivilegeBeforeUpdateHook)
	if err = o.doBeforeUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpdateHook function to empty object, but got: %#v", o)
	}
	rolesPrivilegeBeforeUpdateHooks = []RolesPrivilegeHook{}

	AddRolesPrivilegeHook(boil.AfterUpdateHook, rolesPrivilegeAfterUpdateHook)
	if err = o.doAfterUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpdateHook function to empty object, but got: %#v", o)
	}
	rolesPrivilegeAfterUpdateHooks = []RolesPrivilegeHook{}

	AddRolesPrivilegeHook(boil.BeforeDeleteHook, rolesPrivilegeBeforeDeleteHook)
	if err = o.doBeforeDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeDeleteHook function to empty object, but got: %#v", o)
	}
	rolesPrivilegeBeforeDeleteHooks = []RolesPrivilegeHook{}

	AddRolesPrivilegeHook(boil.AfterDeleteHook, rolesPrivilegeAfterDeleteHook)
	if err = o.doAfterDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterDeleteHook function to empty object, but got: %#v", o)
	}
	rolesPrivilegeAfterDeleteHooks = []RolesPrivilegeHook{}

	AddRolesPrivilegeHook(boil.BeforeUpsertHook, rolesPrivilegeBeforeUpsertHook)
	if err = o.doBeforeUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpsertHook function to empty object, but got: %#v", o)
	}
	rolesPrivilegeBeforeUpsertHooks = []RolesPrivilegeHook{}

	AddRolesPrivilegeHook(boil.AfterUpsertHook, rolesPrivilegeAfterUpsertHook)
	if err = o.doAfterUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpsertHook function to empty object, but got: %#v", o)
	}
	rolesPrivilegeAfterUpsertHooks = []RolesPrivilegeHook{}
}

func testRolesPrivilegesInsert(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RolesPrivilege{}
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := RolesPrivileges().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testRolesPrivilegesInsertWhitelist(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RolesPrivilege{}
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Whitelist(rolesPrivilegeColumnsWithoutDefault...)); err != nil {
		t.Error(err)
	}

	count, err := RolesPrivileges().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testRolesPrivilegesReload(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RolesPrivilege{}
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
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

func testRolesPrivilegesReloadAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RolesPrivilege{}
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := RolesPrivilegeSlice{o}

	if err = slice.ReloadAll(ctx, tx); err != nil {
		t.Error(err)
	}
}

func testRolesPrivilegesSelect(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &RolesPrivilege{}
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := RolesPrivileges().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 1 {
		t.Error("want one record, got:", len(slice))
	}
}

var (
	rolesPrivilegeDBTypes = map[string]string{`RoleID`: `varchar`, `PrivilegeID`: `varchar`}
	_                     = bytes.MinRead
)

func testRolesPrivilegesUpdate(t *testing.T) {
	t.Parallel()

	if 0 == len(rolesPrivilegePrimaryKeyColumns) {
		t.Skip("Skipping table with no primary key columns")
	}
	if len(rolesPrivilegeAllColumns) == len(rolesPrivilegePrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &RolesPrivilege{}
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := RolesPrivileges().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegePrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	if rowsAff, err := o.Update(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only affect one row but affected", rowsAff)
	}
}

func testRolesPrivilegesSliceUpdateAll(t *testing.T) {
	t.Parallel()

	if len(rolesPrivilegeAllColumns) == len(rolesPrivilegePrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &RolesPrivilege{}
	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegeColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := RolesPrivileges().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, rolesPrivilegeDBTypes, true, rolesPrivilegePrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	// Remove Primary keys and unique columns from what we plan to update
	var fields []string
	if strmangle.StringSliceMatch(rolesPrivilegeAllColumns, rolesPrivilegePrimaryKeyColumns) {
		fields = rolesPrivilegeAllColumns
	} else {
		fields = strmangle.SetComplement(
			rolesPrivilegeAllColumns,
			rolesPrivilegePrimaryKeyColumns,
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

	slice := RolesPrivilegeSlice{o}
	if rowsAff, err := slice.UpdateAll(ctx, tx, updateMap); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("wanted one record updated but got", rowsAff)
	}
}

func testRolesPrivilegesUpsert(t *testing.T) {
	t.Parallel()

	if len(rolesPrivilegeAllColumns) == len(rolesPrivilegePrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}
	if len(mySQLRolesPrivilegeUniqueColumns) == 0 {
		t.Skip("Skipping table with no unique columns to conflict on")
	}

	seed := randomize.NewSeed()
	var err error
	// Attempt the INSERT side of an UPSERT
	o := RolesPrivilege{}
	if err = randomize.Struct(seed, &o, rolesPrivilegeDBTypes, false); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert RolesPrivilege: %s", err)
	}

	count, err := RolesPrivileges().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}

	// Attempt the UPDATE side of an UPSERT
	if err = randomize.Struct(seed, &o, rolesPrivilegeDBTypes, false, rolesPrivilegePrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize RolesPrivilege struct: %s", err)
	}

	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert RolesPrivilege: %s", err)
	}

	count, err = RolesPrivileges().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}
}
