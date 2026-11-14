# Called only for new private temporary directories and our own staged file.
discard_library_candidate() {
    if [ -n "$LIBRARY_DIR" ]; then
        rm -f "$LIBRARY_DIR/libcfesp.so"
        rmdir "$LIBRARY_DIR" 2>/dev/null || :
    fi
    rm -f "$RUNTIME/libcfesp-ready.so"
    LIBRARY_DIR=''
    LIBRARY=''
}

prepare_library_candidate() {
    candidate_parent=$1
    [ -d "$candidate_parent" ] || return 1
    LIBRARY_DIR=$(mktemp -d "$candidate_parent/cfesp-launch.XXXXXXXX" 2>/dev/null) || {
        LIBRARY_DIR=''
        PREPARE_FAILURE='создание временного каталога'
        return 1
    }
    LIBRARY="$LIBRARY_DIR/libcfesp.so"
    if [ "$SELINUX_MODE" != Disabled ]; then
        directory_context=$(read_context "$candidate_parent")
        if [ -z "$directory_context" ] || ! chcon "$directory_context" "$LIBRARY_DIR" 2>/dev/null; then
            PREPARE_FAILURE='контекст временного каталога'
            discard_library_candidate
            return 1
        fi
    fi
    if ! chmod 755 "$LIBRARY_DIR"; then
        PREPARE_FAILURE='права временного каталога'
        discard_library_candidate
        return 1
    fi
    # Write in our root-owned staging directory, not in the installed APK tree.
    # The shell opens the output itself; no external cp creates the target.
    if ! cat "$RUNTIME/libcfesp.so" > "$RUNTIME/libcfesp-ready.so"; then
        PREPARE_FAILURE='запись промежуточной библиотеки'
        discard_library_candidate
        return 1
    fi
    if ! chmod 644 "$RUNTIME/libcfesp-ready.so"; then
        PREPARE_FAILURE='права промежуточной библиотеки'
        discard_library_candidate
        return 1
    fi
    if [ "$SELINUX_MODE" != Disabled ] && ! chcon "$APP_CONTEXT" "$RUNTIME/libcfesp-ready.so" 2>/dev/null; then
        PREPARE_FAILURE='контекст промежуточной библиотеки'
        discard_library_candidate
        return 1
    fi
    # Rename an existing, labelled file instead of creating a new .so in /data/app.
    if ! mv "$RUNTIME/libcfesp-ready.so" "$LIBRARY" 2>/dev/null; then
        PREPARE_FAILURE='размещение подготовленной библиотеки'
        discard_library_candidate
        return 1
    fi
    if [ "$SELINUX_MODE" != Disabled ]; then
        if ! chcon "$APP_CONTEXT" "$LIBRARY" 2>/dev/null ||
           [ "$(read_context "$LIBRARY_DIR")" != "$directory_context" ] ||
           [ "$(read_context "$LIBRARY")" != "$APP_CONTEXT" ]; then
            PREPARE_FAILURE='проверка конечного контекста'
            discard_library_candidate
            return 1
        fi
    fi
    if ! chmod 644 "$LIBRARY"; then
        PREPARE_FAILURE='права библиотеки'
        discard_library_candidate
        return 1
    fi
    return 0
}

prepare_library() {
    APK_PATH=$(pm path --user "$USER_ID" "$PACKAGE" | sed -n 's/^package://p' | head -n 1)
    [ -n "$APK_PATH" ] || fail 'Не удалось определить каталог установленной игры.'
    APK_PATH=$(readlink -f "$APK_PATH") || fail 'Не удалось определить путь APK.'
    INSTALL_DIR=$(dirname "$APK_PATH")
    case "$INSTALL_DIR" in
        /data/app/*|/mnt/expand/*/app/*) ;;
        *) fail 'Игра должна быть установлена как обычное приложение в /data/app или /mnt/expand.' ;;
    esac
    NATIVE_REF="$INSTALL_DIR/lib/arm64/libunity.so"
    [ -f "$NATIVE_REF" ] || fail 'Не найдена извлечённая ARM64 libunity.so в установленной игре.'
    NATIVE_REF=$(readlink -f "$NATIVE_REF") || fail 'Не удалось определить путь libunity.so.'
    case "$NATIVE_REF" in
        "$INSTALL_DIR"/*) ;;
        *) fail 'libunity.so находится вне каталога выбранной игры; загрузка отменена.' ;;
    esac
    [ -f "$NATIVE_REF" ] || fail 'Установленная libunity.so недоступна.'
    NATIVE_DIR=$(dirname "$NATIVE_REF")
    SELINUX_MODE=$(getenforce 2>/dev/null || printf 'Unknown')
    APP_CONTEXT=''
    if [ "$SELINUX_MODE" != Disabled ]; then
        command -v chcon >/dev/null 2>&1 || fail 'Нет chcon для контекста библиотеки.'
        APP_CONTEXT=$(read_context "$NATIVE_REF")
        [ -n "$APP_CONTEXT" ] || fail 'Не удалось прочитать SELinux-контекст установленной библиотеки.'
    fi
    PREPARE_FAILURE=''
    if prepare_library_candidate "$NATIVE_DIR"; then
        printf '%s\n' 'Подготовлена библиотека рядом с файлами установленной игры.'
    else
        printf 'Каталог APK недоступен (%s). Проверяю отдельный каталог данных игры...\n' "$PREPARE_FAILURE"
        APP_DATA_DIR=$(readlink -f "/data/user/$USER_ID/$PACKAGE" 2>/dev/null || :)
        case "$APP_DATA_DIR" in
            /data/user/"$USER_ID"/"$PACKAGE"|/mnt/expand/*/user/"$USER_ID"/"$PACKAGE") ;;
            /data/data/"$PACKAGE") [ "$USER_ID" = 0 ] || fail 'Каталог данных относится к другому пользователю.' ;;
            *) fail 'Не удалось проверить каталог данных выбранной игры.' ;;
        esac
        [ -d "$APP_DATA_DIR" ] || fail 'Каталог данных игры недоступен root-процессу.'
        candidate_parent="$APP_DATA_DIR"
        if [ -d "$APP_DATA_DIR/code_cache" ]; then candidate_parent="$APP_DATA_DIR/code_cache"; fi
        if ! prepare_library_candidate "$candidate_parent"; then
            fail "Root-процессу запрещена подготовка библиотеки: $PREPARE_FAILURE. SELinux: $SELINUX_MODE."
        fi
        printf '%s\n' 'Подготовлена библиотека в отдельном подкаталоге данных игры.'
    fi
    ACTUAL=$(sha256sum "$LIBRARY")
    [ "${ACTUAL%% *}" = '981ac3443956ec285d4d6292db0e6f63e88c3e722dbc869c341c9d596bc1bf7d' ] || fail 'Копия библиотеки повреждена.'
}
