const assert = require("assert");
const {
  default: sift,
  createQueryTester,
  ...defaultOperations
} = require("../lib");

// A string `$where` body is compiled with `new Function` (arbitrary code
// execution). It stays enabled by default for backwards compatibility, but
// callers that accept untrusted queries can turn it off with
// `{ allowStringWhere: false }`. See CVE-2026-85625.
describe(__filename + "#", function () {
  it("runs a string $where by default", function () {
    const test = sift({ $where: "this.v === 1" });
    assert.deepEqual([{ v: 1 }, { v: 2 }].filter(test), [{ v: 1 }]);
  });

  it("exposes the `obj` argument to a string $where", function () {
    const test = sift({ $where: "obj.v === 1" });
    assert.deepEqual([{ v: 1 }, { v: 2 }].filter(test), [{ v: 1 }]);
  });

  it("throws on a string $where when allowStringWhere is false", function () {
    assert.throws(
      () => sift({ $where: "this.v === 1" }, { allowStringWhere: false }),
      /allowStringWhere/,
    );
  });

  it("throws on a nested string $where when allowStringWhere is false", function () {
    assert.throws(
      () => sift({ a: { $where: "true" } }, { allowStringWhere: false }),
      /allowStringWhere/,
    );
  });

  [
    ["$and", { $and: [{ $where: "true" }] }],
    ["$or", { $or: [{ $where: "true" }] }],
    ["$nor", { $nor: [{ $where: "true" }] }],
    ["$not on a property", { a: { $not: { $where: "true" } } }],
    ["$elemMatch", { a: { $elemMatch: { $where: "true" } } }],
    ["deeply nested $and/$or", { $and: [{ $or: [{ $where: "true" }] }] }],
  ].forEach(function ([label, query]) {
    it(`throws on a string $where inside ${label} when allowStringWhere is false`, function () {
      assert.throws(
        () => sift(query, { allowStringWhere: false }),
        /allowStringWhere/,
      );
    });
  });

  it("does not affect operator-free queries when allowStringWhere is false", function () {
    const test = sift(
      { a: { $gt: 1 }, $or: [{ b: 2 }, { c: 3 }] },
      { allowStringWhere: false },
    );
    assert.deepEqual([{ a: 2, b: 2 }, { a: 0 }, { a: 5, c: 3 }].filter(test), [
      { a: 2, b: 2 },
      { a: 5, c: 3 },
    ]);
  });

  it("permits a string $where when allowStringWhere is explicitly true", function () {
    const test = sift({ $where: "this.v === 1" }, { allowStringWhere: true });
    assert.deepEqual([{ v: 1 }, { v: 2 }].filter(test), [{ v: 1 }]);
  });

  it("treats allowStringWhere: undefined as the permissive default", function () {
    const test = sift(
      { $where: "this.v === 1" },
      { allowStringWhere: undefined },
    );
    assert.deepEqual([{ v: 1 }, { v: 2 }].filter(test), [{ v: 1 }]);
  });

  it("still allows a function $where when allowStringWhere is false", function () {
    const test = sift(
      {
        $where: function () {
          return this.v === 1;
        },
      },
      { allowStringWhere: false },
    );
    assert.deepEqual([{ v: 1 }, { v: 2 }].filter(test), [{ v: 1 }]);
  });

  it("honours allowStringWhere:false through createQueryTester too", function () {
    assert.throws(
      () =>
        createQueryTester(
          { $where: "this.v === 1" },
          { operations: defaultOperations, allowStringWhere: false },
        ),
      /allowStringWhere/,
    );
  });
});
