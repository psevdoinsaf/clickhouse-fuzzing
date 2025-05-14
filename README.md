### Как запустить
Взять снапшот кх, [здесь](https://github.com/awslabs/snapchange/tree/main/qemu_snapshot) подробно описано как снимать снапшот с помощью QEMU.

Далее кладем снапшот в файл `clickhouse` и запускаем:

```console
$ cargo run -r -- fuzz -c 16
```

Результаты работы лежат в папке `crashes`.