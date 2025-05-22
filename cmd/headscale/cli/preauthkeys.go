package cli

import (
	"fmt"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/common/model"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
	"os"
	"strconv"
	"strings"
	"time"
	"zgo.at/zcache/v2"
)

const (
	DefaultPreAuthKeyExpiry = "1h"
)

func init() {
	rootCmd.AddCommand(preauthkeysCmd)
	preauthkeysCmd.PersistentFlags().Uint64P("user", "u", 0, "User identifier (ID)")

	preauthkeysCmd.PersistentFlags().StringP("namespace", "n", "", "User")
	//pakNamespaceFlag := preauthkeysCmd.PersistentFlags().Lookup("namespace")
	//pakNamespaceFlag.Deprecated = deprecateNamespaceMessage
	//pakNamespaceFlag.Hidden = true

	//err := preauthkeysCmd.MarkPersistentFlagRequired("user")
	//if err != nil {
	//	log.Fatal().Err(err).Msg("")
	//}

	preauthkeysCmd.AddCommand(listPreAuthKeys)
	preauthkeysCmd.AddCommand(createPreAuthKeyCmd)
	preauthkeysCmd.AddCommand(expirePreAuthKeyCmd)
	createPreAuthKeyCmd.PersistentFlags().
		Bool("reusable", false, "Make the preauthkey reusable")
	createPreAuthKeyCmd.PersistentFlags().
		Bool("ephemeral", false, "Preauthkey for ephemeral nodes")
	createPreAuthKeyCmd.Flags().
		StringP("expiration", "e", DefaultPreAuthKeyExpiry, "Human-readable expiration of the key (e.g. 30m, 24h)")
	createPreAuthKeyCmd.Flags().
		StringSlice("tags", []string{}, "Tags to automatically assign to node")
}

var preauthkeysCmd = &cobra.Command{
	Use:     "preauthkeys",
	Short:   "Handle the preauthkeys in Headscale",
	Aliases: []string{"preauthkey", "authkey", "pre"},
}

var listPreAuthKeys = &cobra.Command{
	Use:     "list",
	Short:   "List the preauthkeys for this user",
	Aliases: []string{"ls", "show"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		user, err := cmd.Flags().GetUint64("user")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting user: %s", err), output)
		}

		ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
		defer cancel()
		defer conn.Close()

		request := &v1.ListPreAuthKeysRequest{
			User: user,
		}

		response, err := client.ListPreAuthKeys(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting the list of keys: %s", err),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response.GetPreAuthKeys(), "", output)
		}

		tableData := pterm.TableData{
			{
				"ID",
				"Key",
				"Reusable",
				"Ephemeral",
				"Used",
				"Expiration",
				"Created",
				"Tags",
			},
		}
		for _, key := range response.GetPreAuthKeys() {
			expiration := "-"
			if key.GetExpiration() != nil {
				expiration = ColourTime(key.GetExpiration().AsTime())
			}

			aclTags := ""

			for _, tag := range key.GetAclTags() {
				aclTags += "," + tag
			}

			aclTags = strings.TrimLeft(aclTags, ",")

			tableData = append(tableData, []string{
				strconv.FormatUint(key.GetId(), 10),
				key.GetKey(),
				strconv.FormatBool(key.GetReusable()),
				strconv.FormatBool(key.GetEphemeral()),
				strconv.FormatBool(key.GetUsed()),
				expiration,
				key.GetCreatedAt().AsTime().Format("2006-01-02 15:04:05"),
				aclTags,
			})

		}
		err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Failed to render pterm table: %s", err),
				output,
			)
		}
	},
}

var (
	registerCacheExpiration = time.Minute * 15
	registerCacheCleanup    = time.Minute * 20
)

var createPreAuthKeyCmd = &cobra.Command{
	Use:     "create",
	Short:   "Creates a new preauthkey in the specified user",
	Aliases: []string{"c", "new"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		user, err := cmd.Flags().GetUint64("user")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting user: %s", err), output)
		}

		if user == 0 {
			cfg, err := types.LoadServerConfig()
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Error loading config: %s", err), output)
			}

			registrationCache := zcache.New[types.RegistrationID, types.RegisterNode](
				registerCacheExpiration,
				registerCacheCleanup,
			)
			dbHandler, err := db.NewHeadscaleDatabase(
				cfg.Database,
				cfg.BaseDomain,
				registrationCache,
			)
			defer func(dbHandler *db.HSDatabase) {
				if dbHandler == nil {
					return
				}
				err := dbHandler.Close()
				if err != nil {
					log.Error().Err(err).Msg("Error closing database connection")
				}
			}(dbHandler)

			namespace, err := cmd.Flags().GetString("namespace")
			if err == nil && namespace != "" {
				userInfo, err := dbHandler.GetUserByName(namespace)
				if err == nil {
					user = uint64(userInfo.ID)
				}
			}
		}
		if user == 0 {
			_ = cmd.Help()
			_, _ = fmt.Fprintf(os.Stderr, "%s\n", "Error: No user specified")
			return
		}

		reusable, _ := cmd.Flags().GetBool("reusable")
		ephemeral, _ := cmd.Flags().GetBool("ephemeral")
		tags, _ := cmd.Flags().GetStringSlice("tags")

		request := &v1.CreatePreAuthKeyRequest{
			User:      user,
			Reusable:  reusable,
			Ephemeral: ephemeral,
			AclTags:   tags,
		}

		durationStr, _ := cmd.Flags().GetString("expiration")

		duration, err := model.ParseDuration(durationStr)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Could not parse duration: %s\n", err),
				output,
			)
		}

		expiration := time.Now().UTC().Add(time.Duration(duration))

		log.Trace().
			Dur("expiration", time.Duration(duration)).
			Msg("expiration has been set")

		request.Expiration = timestamppb.New(expiration)

		ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
		defer cancel()
		defer conn.Close()

		response, err := client.CreatePreAuthKey(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot create Pre Auth Key: %s\n", err),
				output,
			)
		}

		SuccessOutput(response.GetPreAuthKey(), response.GetPreAuthKey().GetKey(), output)
	},
}

var expirePreAuthKeyCmd = &cobra.Command{
	Use:     "expire KEY",
	Short:   "Expire a preauthkey",
	Aliases: []string{"revoke", "exp", "e"},
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		user, err := cmd.Flags().GetUint64("user")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting user: %s", err), output)
		}

		ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
		defer cancel()
		defer conn.Close()

		request := &v1.ExpirePreAuthKeyRequest{
			User: user,
			Key:  args[0],
		}

		response, err := client.ExpirePreAuthKey(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot expire Pre Auth Key: %s\n", err),
				output,
			)
		}

		SuccessOutput(response, "Key expired", output)
	},
}
