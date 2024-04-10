#!/bin/bash

# Проверяем, что переданы обязательные параметры
if [ "$#" -lt 2 ]; then
    echo "Использование: $0 -p <порт> [-c]"
    exit 1
fi

# По умолчанию устанавливаем значение $c в 0
c=0

# Парсим параметры командной строки
while getopts ":h:p:c" opt; do
    case ${opt} in
        h )
            host=$OPTARG
            ;;
        p )
            port=$OPTARG
            ;;
        c )
            c=1
            ;;
        \? )
            echo "Неизвестный параметр: -$OPTARG" >&2
            exit 1
            ;;
        : )
            echo "Отсутствует аргумент для параметра: -$OPTARG" >&2
            exit 1
            ;;
    esac
done
shift $((OPTIND -1))

# Запускаем вашу программу на языке C с полученными параметрами и значением $c
build/server "$port" "$c"

