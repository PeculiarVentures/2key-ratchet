import * as assert from "assert";
import { AssocStorage } from "../src/storage";

context("AssocStorage", () => {

    it("all", () => {

        const store = new AssocStorage<number>();

        assert.equal(store.length, 0);

        store.save("1", 1);
        store.save("2", 2);
        store.save("3", 3);

        assert.equal(store.length, 3);

        assert.equal(store.load("1"), 1);
        assert.equal(store.load("2"), 2);
        assert.equal(store.load("wrong"), void 0);

        store.remove("2");

        assert.equal(store.length, 2);
        assert.equal(store.load("2"), void 0);

        store.clear();
        assert.equal(store.length, 0);
    });

});
