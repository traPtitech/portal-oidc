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

func testClients(t *testing.T) {
	t.Parallel()

	query := Clients()

	if query.Query == nil {
		t.Error("expected a query, got nothing")
	}
}

func testClientsDelete(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Client{}
	if err = randomize.Struct(seed, o, clientDBTypes, true, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
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

	count, err := Clients().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testClientsQueryDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Client{}
	if err = randomize.Struct(seed, o, clientDBTypes, true, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if rowsAff, err := Clients().DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := Clients().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testClientsSliceDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Client{}
	if err = randomize.Struct(seed, o, clientDBTypes, true, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := ClientSlice{o}

	if rowsAff, err := slice.DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := Clients().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testClientsExists(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Client{}
	if err = randomize.Struct(seed, o, clientDBTypes, true, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	e, err := ClientExists(ctx, tx, o.ID)
	if err != nil {
		t.Errorf("Unable to check if Client exists: %s", err)
	}
	if !e {
		t.Errorf("Expected ClientExists to return true, but got false.")
	}
}

func testClientsFind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Client{}
	if err = randomize.Struct(seed, o, clientDBTypes, true, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	clientFound, err := FindClient(ctx, tx, o.ID)
	if err != nil {
		t.Error(err)
	}

	if clientFound == nil {
		t.Error("want a record, got nil")
	}
}

func testClientsBind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Client{}
	if err = randomize.Struct(seed, o, clientDBTypes, true, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if err = Clients().Bind(ctx, tx, o); err != nil {
		t.Error(err)
	}
}

func testClientsOne(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Client{}
	if err = randomize.Struct(seed, o, clientDBTypes, true, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if x, err := Clients().One(ctx, tx); err != nil {
		t.Error(err)
	} else if x == nil {
		t.Error("expected to get a non nil record")
	}
}

func testClientsAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	clientOne := &Client{}
	clientTwo := &Client{}
	if err = randomize.Struct(seed, clientOne, clientDBTypes, false, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}
	if err = randomize.Struct(seed, clientTwo, clientDBTypes, false, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = clientOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = clientTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := Clients().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 2 {
		t.Error("want 2 records, got:", len(slice))
	}
}

func testClientsCount(t *testing.T) {
	t.Parallel()

	var err error
	seed := randomize.NewSeed()
	clientOne := &Client{}
	clientTwo := &Client{}
	if err = randomize.Struct(seed, clientOne, clientDBTypes, false, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}
	if err = randomize.Struct(seed, clientTwo, clientDBTypes, false, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = clientOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = clientTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Clients().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 2 {
		t.Error("want 2 records, got:", count)
	}
}

func clientBeforeInsertHook(ctx context.Context, e boil.ContextExecutor, o *Client) error {
	*o = Client{}
	return nil
}

func clientAfterInsertHook(ctx context.Context, e boil.ContextExecutor, o *Client) error {
	*o = Client{}
	return nil
}

func clientAfterSelectHook(ctx context.Context, e boil.ContextExecutor, o *Client) error {
	*o = Client{}
	return nil
}

func clientBeforeUpdateHook(ctx context.Context, e boil.ContextExecutor, o *Client) error {
	*o = Client{}
	return nil
}

func clientAfterUpdateHook(ctx context.Context, e boil.ContextExecutor, o *Client) error {
	*o = Client{}
	return nil
}

func clientBeforeDeleteHook(ctx context.Context, e boil.ContextExecutor, o *Client) error {
	*o = Client{}
	return nil
}

func clientAfterDeleteHook(ctx context.Context, e boil.ContextExecutor, o *Client) error {
	*o = Client{}
	return nil
}

func clientBeforeUpsertHook(ctx context.Context, e boil.ContextExecutor, o *Client) error {
	*o = Client{}
	return nil
}

func clientAfterUpsertHook(ctx context.Context, e boil.ContextExecutor, o *Client) error {
	*o = Client{}
	return nil
}

func testClientsHooks(t *testing.T) {
	t.Parallel()

	var err error

	ctx := context.Background()
	empty := &Client{}
	o := &Client{}

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, o, clientDBTypes, false); err != nil {
		t.Errorf("Unable to randomize Client object: %s", err)
	}

	AddClientHook(boil.BeforeInsertHook, clientBeforeInsertHook)
	if err = o.doBeforeInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeInsertHook function to empty object, but got: %#v", o)
	}
	clientBeforeInsertHooks = []ClientHook{}

	AddClientHook(boil.AfterInsertHook, clientAfterInsertHook)
	if err = o.doAfterInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterInsertHook function to empty object, but got: %#v", o)
	}
	clientAfterInsertHooks = []ClientHook{}

	AddClientHook(boil.AfterSelectHook, clientAfterSelectHook)
	if err = o.doAfterSelectHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterSelectHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterSelectHook function to empty object, but got: %#v", o)
	}
	clientAfterSelectHooks = []ClientHook{}

	AddClientHook(boil.BeforeUpdateHook, clientBeforeUpdateHook)
	if err = o.doBeforeUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpdateHook function to empty object, but got: %#v", o)
	}
	clientBeforeUpdateHooks = []ClientHook{}

	AddClientHook(boil.AfterUpdateHook, clientAfterUpdateHook)
	if err = o.doAfterUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpdateHook function to empty object, but got: %#v", o)
	}
	clientAfterUpdateHooks = []ClientHook{}

	AddClientHook(boil.BeforeDeleteHook, clientBeforeDeleteHook)
	if err = o.doBeforeDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeDeleteHook function to empty object, but got: %#v", o)
	}
	clientBeforeDeleteHooks = []ClientHook{}

	AddClientHook(boil.AfterDeleteHook, clientAfterDeleteHook)
	if err = o.doAfterDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterDeleteHook function to empty object, but got: %#v", o)
	}
	clientAfterDeleteHooks = []ClientHook{}

	AddClientHook(boil.BeforeUpsertHook, clientBeforeUpsertHook)
	if err = o.doBeforeUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpsertHook function to empty object, but got: %#v", o)
	}
	clientBeforeUpsertHooks = []ClientHook{}

	AddClientHook(boil.AfterUpsertHook, clientAfterUpsertHook)
	if err = o.doAfterUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpsertHook function to empty object, but got: %#v", o)
	}
	clientAfterUpsertHooks = []ClientHook{}
}

func testClientsInsert(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Client{}
	if err = randomize.Struct(seed, o, clientDBTypes, true, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Clients().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testClientsInsertWhitelist(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Client{}
	if err = randomize.Struct(seed, o, clientDBTypes, true); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Whitelist(clientColumnsWithoutDefault...)); err != nil {
		t.Error(err)
	}

	count, err := Clients().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testClientToManyRedirectUris(t *testing.T) {
	var err error
	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()

	var a Client
	var b, c RedirectURI

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, &a, clientDBTypes, true, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	if err := a.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	if err = randomize.Struct(seed, &b, redirectURIDBTypes, false, redirectURIColumnsWithDefault...); err != nil {
		t.Fatal(err)
	}
	if err = randomize.Struct(seed, &c, redirectURIDBTypes, false, redirectURIColumnsWithDefault...); err != nil {
		t.Fatal(err)
	}

	b.ClientID = a.ID
	c.ClientID = a.ID

	if err = b.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}
	if err = c.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	check, err := a.RedirectUris().All(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}

	bFound, cFound := false, false
	for _, v := range check {
		if v.ClientID == b.ClientID {
			bFound = true
		}
		if v.ClientID == c.ClientID {
			cFound = true
		}
	}

	if !bFound {
		t.Error("expected to find b")
	}
	if !cFound {
		t.Error("expected to find c")
	}

	slice := ClientSlice{&a}
	if err = a.L.LoadRedirectUris(ctx, tx, false, (*[]*Client)(&slice), nil); err != nil {
		t.Fatal(err)
	}
	if got := len(a.R.RedirectUris); got != 2 {
		t.Error("number of eager loaded records wrong, got:", got)
	}

	a.R.RedirectUris = nil
	if err = a.L.LoadRedirectUris(ctx, tx, true, &a, nil); err != nil {
		t.Fatal(err)
	}
	if got := len(a.R.RedirectUris); got != 2 {
		t.Error("number of eager loaded records wrong, got:", got)
	}

	if t.Failed() {
		t.Logf("%#v", check)
	}
}

func testClientToManyAddOpRedirectUris(t *testing.T) {
	var err error

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()

	var a Client
	var b, c, d, e RedirectURI

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, &a, clientDBTypes, false, strmangle.SetComplement(clientPrimaryKeyColumns, clientColumnsWithoutDefault)...); err != nil {
		t.Fatal(err)
	}
	foreigners := []*RedirectURI{&b, &c, &d, &e}
	for _, x := range foreigners {
		if err = randomize.Struct(seed, x, redirectURIDBTypes, false, strmangle.SetComplement(redirectURIPrimaryKeyColumns, redirectURIColumnsWithoutDefault)...); err != nil {
			t.Fatal(err)
		}
	}

	if err := a.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}
	if err = b.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}
	if err = c.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	foreignersSplitByInsertion := [][]*RedirectURI{
		{&b, &c},
		{&d, &e},
	}

	for i, x := range foreignersSplitByInsertion {
		err = a.AddRedirectUris(ctx, tx, i != 0, x...)
		if err != nil {
			t.Fatal(err)
		}

		first := x[0]
		second := x[1]

		if a.ID != first.ClientID {
			t.Error("foreign key was wrong value", a.ID, first.ClientID)
		}
		if a.ID != second.ClientID {
			t.Error("foreign key was wrong value", a.ID, second.ClientID)
		}

		if first.R.Client != &a {
			t.Error("relationship was not added properly to the foreign slice")
		}
		if second.R.Client != &a {
			t.Error("relationship was not added properly to the foreign slice")
		}

		if a.R.RedirectUris[i*2] != first {
			t.Error("relationship struct slice not set to correct value")
		}
		if a.R.RedirectUris[i*2+1] != second {
			t.Error("relationship struct slice not set to correct value")
		}

		count, err := a.RedirectUris().Count(ctx, tx)
		if err != nil {
			t.Fatal(err)
		}
		if want := int64((i + 1) * 2); count != want {
			t.Error("want", want, "got", count)
		}
	}
}

func testClientsReload(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Client{}
	if err = randomize.Struct(seed, o, clientDBTypes, true, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
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

func testClientsReloadAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Client{}
	if err = randomize.Struct(seed, o, clientDBTypes, true, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := ClientSlice{o}

	if err = slice.ReloadAll(ctx, tx); err != nil {
		t.Error(err)
	}
}

func testClientsSelect(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Client{}
	if err = randomize.Struct(seed, o, clientDBTypes, true, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := Clients().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 1 {
		t.Error("want one record, got:", len(slice))
	}
}

var (
	clientDBTypes = map[string]string{`ID`: `char`, `Name`: `text`, `Description`: `text`, `SecretKey`: `text`, `CreatedAt`: `datetime`, `UpdatedAt`: `datetime`}
	_             = bytes.MinRead
)

func testClientsUpdate(t *testing.T) {
	t.Parallel()

	if 0 == len(clientPrimaryKeyColumns) {
		t.Skip("Skipping table with no primary key columns")
	}
	if len(clientAllColumns) == len(clientPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &Client{}
	if err = randomize.Struct(seed, o, clientDBTypes, true, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Clients().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, clientDBTypes, true, clientPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	if rowsAff, err := o.Update(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only affect one row but affected", rowsAff)
	}
}

func testClientsSliceUpdateAll(t *testing.T) {
	t.Parallel()

	if len(clientAllColumns) == len(clientPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &Client{}
	if err = randomize.Struct(seed, o, clientDBTypes, true, clientColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Clients().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, clientDBTypes, true, clientPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	// Remove Primary keys and unique columns from what we plan to update
	var fields []string
	if strmangle.StringSliceMatch(clientAllColumns, clientPrimaryKeyColumns) {
		fields = clientAllColumns
	} else {
		fields = strmangle.SetComplement(
			clientAllColumns,
			clientPrimaryKeyColumns,
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

	slice := ClientSlice{o}
	if rowsAff, err := slice.UpdateAll(ctx, tx, updateMap); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("wanted one record updated but got", rowsAff)
	}
}

func testClientsUpsert(t *testing.T) {
	t.Parallel()

	if len(clientAllColumns) == len(clientPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}
	if len(mySQLClientUniqueColumns) == 0 {
		t.Skip("Skipping table with no unique columns to conflict on")
	}

	seed := randomize.NewSeed()
	var err error
	// Attempt the INSERT side of an UPSERT
	o := Client{}
	if err = randomize.Struct(seed, &o, clientDBTypes, false); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert Client: %s", err)
	}

	count, err := Clients().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}

	// Attempt the UPDATE side of an UPSERT
	if err = randomize.Struct(seed, &o, clientDBTypes, false, clientPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Client struct: %s", err)
	}

	if err = o.Upsert(ctx, tx, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert Client: %s", err)
	}

	count, err = Clients().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}
}
