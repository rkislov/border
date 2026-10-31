// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rkislov/border/internal/backup"
	"github.com/spf13/cobra"
)

func backupCommand() *cobra.Command {
	var config, key, temp string
	var maxBytes int64
	b := &cobra.Command{Use: "backup", Short: "Зашифрованные резервные копии SQLite и проверка восстановления"}
	b.PersistentFlags().StringVar(&config, "config", "/etc/border-backup.json", "Конфигурация резервного копирования, доступная только администратору ОС")
	for _, name := range []string{"run", "tick"} {
		name := name
		b.AddCommand(&cobra.Command{Use: name, Short: map[string]string{"run": "Создать и проверить полную копию сейчас", "tick": "Обработать расписание и одну заявку из панели"}[name], Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
			v, e := backup.LoadConfig(config)
			if e != nil {
				return e
			}
			ctx, cancel := context.WithTimeout(c.Context(), 30*time.Minute)
			defer cancel()
			j, e := backup.Process(ctx, v, name == "run")
			if j != nil {
				json.NewEncoder(c.OutOrStdout()).Encode(j)
			}
			return e
		}})
	}
	init := &cobra.Command{Use: "init-key PATH", Short: "Создать отдельный ключ архива (без перезаписи и вывода секрета)", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error { return backup.InitIdentity(args[0]) }}
	b.AddCommand(init)
	b.AddCommand(&cobra.Command{Use: "init-file-export", Short: "Привязать существующую сетевую папку к назначению FileExport", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		v, e := backup.LoadConfig(config)
		if e != nil {
			return e
		}
		return backup.InitFileExport(v)
	}})
	for _, name := range []string{"verify", "restore"} {
		name := name
		cmd := &cobra.Command{Use: name + " ARCHIVE", Short: map[string]string{"verify": "Расшифровать и проверить восстановление во временном каталоге", "restore": "Восстановить в НОВЫЙ каталог; работающий сервер не изменяется"}[name], Args: cobra.ExactArgs(1)}
		var destination string
		cmd.Flags().StringVar(&key, "key", "", "Отдельный ключ age")
		cmd.MarkFlagRequired("key")
		cmd.Flags().StringVar(&temp, "temp-dir", "", "Родитель временного каталога проверки")
		cmd.Flags().Int64Var(&maxBytes, "max-bytes", 4<<30, "Лимит распакованных данных")
		if name == "restore" {
			cmd.Flags().StringVar(&destination, "to", "", "Новый абсолютный путь")
			cmd.MarkFlagRequired("to")
		}
		cmd.RunE = func(c *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(c.Context(), 30*time.Minute)
			defer cancel()
			var r backup.Report
			var e error
			if name == "verify" {
				r, e = backup.Verify(ctx, args[0], key, temp, maxBytes)
			} else {
				r, e = backup.Restore(ctx, args[0], key, destination, maxBytes)
			}
			if e != nil {
				return e
			}
			return json.NewEncoder(c.OutOrStdout()).Encode(r)
		}
		b.AddCommand(cmd)
	}
	return b
}
