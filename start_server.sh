#!/bin/bash

# Проверяем, что переданы обязательные параметры
if [ "$#" -lt 2 ]; then
    echo "Использование: $0 -p <порт> -m <режим>"
    exit 1
fi

# По умолчанию устанавливаем значение $m

m=0

# Парсим параметры командной строки
while getopts ":p:m:" opt; do
    case ${opt} in
        p )
            port=$OPTARG
            ;;
        m )
            m=$OPTARG
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

# Запускаем рограмму с полученными параметрами и значением $m
build/server "$port" "$m"

