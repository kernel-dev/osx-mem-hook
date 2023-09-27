# macOS Memory Hook

This is just a small project that I decided to make to get myself into a bit of reverse engineering, and understanding the ecosystem of macOS.

## Running the project

First, compile and run `dummy_process.c`:

```bash
clang src/dummy_process.c -o dummy && ./dummy
```

<br />

Afterwards, compile the injector:

```bash
clang -Iinc -lm src/main.c src/hook/hook.c -o hook
```

Now, after running `dummy`, you run `hook`. The `Hello World` string should now be changed to `All your code are belong to us!` in the runtime.
