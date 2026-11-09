# cortex9-lact-polkit-pid-subject-bypass-model

Modelo offline de **CVE-2026-75037** (CNA SUSE, bsc#1276480): el daemon de
LACT le preguntaba a Polkit por un cliente identificado solo por su PID
(`Subject::new_for_owner(pid, None, None)`). Un cliente que manda un pedido
y deja que un proceso privilegiado tome su PID antes del chequeo puede ser
juzgado como ese proceso; los hooks de perfil corren como root (informe de
SUSE). NVD y cve.org: "hasta 0.10.0. Corregido por el commit d0478fe", que
pasa el uid de `SO_PEERCRED`. Después, el autor de LACT encontró que
zbus_polkit 5.0.0 manda ese uid como `u32` y polkitd espera `int32`, así
que el uid se descarta y la carrera sigue (z-galaxy/zbus_polkit PR 101);
40dcf29 (en v0.10.1) parchea el crate y agrega un `pidfd`.
Educativo, determinista, C11 con ASan/UBSan. **No se crean procesos ni se
llama a D-Bus ni a Polkit.**

## Qué se modela

Cuatro versiones de `check_auth()` con sus líneas (ver README en inglés):
`pre` (032f779 = v0.10.0), `d0478fe` (con zbus_polkit 5.0.0), `i32` (un "qué
pasaría si": d0478fe con el crate corregido, no publicado) y `v0101`
(40dcf29 = v0.10.1). Lo que hace polkitd **no** sale de código: sigue el
texto del PR 101 y dos supuestos marcados (pidfd de un cliente muerto
falla; comparar start-time es opcional).

## Evidencia diferencial

En 160 escenarios (`results/sweep.csv`): bypass en `pre` 6, **`d0478fe`
6**, `i32` 0, `v0101` 0. En una grilla de 1.440 escenarios, `d0478fe`
decide igual que `pre` siempre: con zbus_polkit 5.0.0, el commit nombrado
como fix no cambia el resultado en este modelo.

## Uso

```sh
sh scripts/build.sh test
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
./build/lactpk case 1000 0 reuse_before_check 1 1 0
```

Fuentes: [SOURCES.md](SOURCES.md). Límites: [LIMITATIONS.md](LIMITATIONS.md).
Ejercicios: [PRACTICE.md](PRACTICE.md). Licencia: Apache-2.0.
