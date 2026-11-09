# Guía práctica (7 niveles)

Ejercicios **offline y locales** sobre cómo se identifica a un cliente ante
Polkit. No se crean procesos, no se llama a D-Bus ni a Polkit. Cada
respuesta está comprobada en `tests/test_model.c` (`practice_level_N`),
compilado con ASan/UBSan. Si querés experimentar con Polkit real, hacelo
solo en una VM propia y descartable, con un servicio de juguete tuyo,
nunca contra sistemas de terceros.

Comando: `./build/lactpk case <uid_cliente> <uid_reusador> <evento>
<peercred> <pidfd> <st_check>` (después de `sh scripts/build.sh results
/tmp/r`).

**Básico**

1. **Sin carrera.** Cliente uid 1000, nadie toma su PID, versión `pre`.
   (`practice_level_1`: `CHALLENGE`)
2. **La carrera.** Un proceso root toma el PID después de armar el subject.
   (`practice_level_2`: `pre` `AUTHORIZED`, bypass)
3. **El fix con el nombre del CVE.** Lo mismo en `d0478fe`. ¿Qué uid se
   manda y qué decide polkitd? (`practice_level_3`: uid 1000 enviado como
   `u32`, igual `AUTHORIZED`)

**Intermedio**

4. **El tipo importa.** Lo mismo en `i32`. (`practice_level_4`:
   `CHALLENGE`)
5. **pidfd.** Lo mismo en `v0101` con pidfd disponible. (`practice_level_5`:
   `ERROR`: el cliente ya no existe)

**Avanzado**

6. **¿Y el start-time?** Con `st_check=1` y el cambio después de armar el
   subject, en `pre`. (`practice_level_6`: `ERROR`)
7. **El start-time no alcanza.** El PID ya cambió de dueño *antes* de armar
   el subject. (`practice_level_7`: `pre` `AUTHORIZED`: el daemon leyó el
   start-time del proceso nuevo)

Más allá: agregá un escenario a `fixtures/cases.tsv` con su etiqueta a
mano, regenerá `fixtures/expected.tsv` y comprobá que el modelo coincide.
En tu propio código: ¿identificás al cliente por un número que puede
reciclarse, o por algo atado al proceso (credenciales del socket, pidfd)?
¿Comprobaste que el dato realmente llega con el tipo que espera el otro
lado?
