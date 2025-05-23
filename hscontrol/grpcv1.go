// nolint
package hscontrol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/routes"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

type headscaleV1APIServer struct { // v1.HeadscaleServiceServer
	v1.UnimplementedHeadscaleServiceServer
	h *Headscale
}

func newHeadscaleV1APIServer(h *Headscale) v1.HeadscaleServiceServer {
	return headscaleV1APIServer{
		h: h,
	}
}

func (api headscaleV1APIServer) CreateUser(
	ctx context.Context,
	request *v1.CreateUserRequest,
) (*v1.CreateUserResponse, error) {
	newUser := types.User{
		Name:          request.GetName(),
		DisplayName:   request.GetDisplayName(),
		Email:         request.GetEmail(),
		ProfilePicURL: request.GetPictureUrl(),
	}
	user, err := api.h.db.CreateUser(newUser)
	if err != nil {
		return nil, err
	}

	err = usersChangedHook(api.h.db, api.h.polMan, api.h.nodeNotifier)
	if err != nil {
		return nil, fmt.Errorf("updating resources using user: %w", err)
	}

	return &v1.CreateUserResponse{User: user.Proto()}, nil
}

func (api headscaleV1APIServer) RenameUser(
	ctx context.Context,
	request *v1.RenameUserRequest,
) (*v1.RenameUserResponse, error) {
	oldUser, err := api.h.db.GetUserByID(types.UserID(request.GetOldId()))
	if err != nil {
		return nil, err
	}

	err = api.h.db.RenameUser(types.UserID(oldUser.ID), request.GetNewName())
	if err != nil {
		return nil, err
	}

	newUser, err := api.h.db.GetUserByName(request.GetNewName())
	if err != nil {
		return nil, err
	}

	return &v1.RenameUserResponse{User: newUser.Proto()}, nil
}

func (api headscaleV1APIServer) DeleteUser(
	ctx context.Context,
	request *v1.DeleteUserRequest,
) (*v1.DeleteUserResponse, error) {
	user, err := api.h.db.GetUserByID(types.UserID(request.GetId()))
	if err != nil {
		return nil, err
	}

	err = api.h.db.DestroyUser(types.UserID(user.ID))
	if err != nil {
		return nil, err
	}

	err = usersChangedHook(api.h.db, api.h.polMan, api.h.nodeNotifier)
	if err != nil {
		return nil, fmt.Errorf("updating resources using user: %w", err)
	}

	return &v1.DeleteUserResponse{}, nil
}

func (api headscaleV1APIServer) ListUsers(
	ctx context.Context,
	request *v1.ListUsersRequest,
) (*v1.ListUsersResponse, error) {
	var err error
	var users []types.User

	switch {
	case request.GetName() != "":
		users, err = api.h.db.ListUsers(&types.User{Name: request.GetName()})
	case request.GetEmail() != "":
		users, err = api.h.db.ListUsers(&types.User{Email: request.GetEmail()})
	case request.GetId() != 0:
		users, err = api.h.db.ListUsers(&types.User{Model: gorm.Model{ID: uint(request.GetId())}})
	default:
		users, err = api.h.db.ListUsers()
	}
	if err != nil {
		return nil, err
	}

	response := make([]*v1.User, len(users))
	for index, user := range users {
		response[index] = user.Proto()
	}

	sort.Slice(response, func(i, j int) bool {
		return response[i].Id < response[j].Id
	})

	return &v1.ListUsersResponse{Users: response}, nil
}

func (api headscaleV1APIServer) CreatePreAuthKey(
	ctx context.Context,
	request *v1.CreatePreAuthKeyRequest,
) (*v1.CreatePreAuthKeyResponse, error) {
	var expiration time.Time
	if request.GetExpiration() != nil {
		expiration = request.GetExpiration().AsTime()
	}

	for _, tag := range request.AclTags {
		err := validateTag(tag)
		if err != nil {
			return &v1.CreatePreAuthKeyResponse{
				PreAuthKey: nil,
			}, status.Error(codes.InvalidArgument, err.Error())
		}
	}

	user, err := api.h.db.GetUserByID(types.UserID(request.GetUser()))
	if err != nil {
		return nil, err
	}

	preAuthKey, err := api.h.db.CreatePreAuthKey(
		types.UserID(user.ID),
		request.GetReusable(),
		request.GetEphemeral(),
		&expiration,
		request.AclTags,
	)
	if err != nil {
		return nil, err
	}

	return &v1.CreatePreAuthKeyResponse{PreAuthKey: preAuthKey.Proto()}, nil
}

func (api headscaleV1APIServer) ExpirePreAuthKey(
	ctx context.Context,
	request *v1.ExpirePreAuthKeyRequest,
) (*v1.ExpirePreAuthKeyResponse, error) {
	err := api.h.db.Write(func(tx *gorm.DB) error {
		preAuthKey, err := db.GetPreAuthKey(tx, request.Key)
		if err != nil {
			return err
		}

		if uint64(preAuthKey.User.ID) != request.GetUser() {
			return fmt.Errorf("preauth key does not belong to user")
		}

		return db.ExpirePreAuthKey(tx, preAuthKey)
	})
	if err != nil {
		return nil, err
	}

	return &v1.ExpirePreAuthKeyResponse{}, nil
}

func (api headscaleV1APIServer) ListPreAuthKeys(
	ctx context.Context,
	request *v1.ListPreAuthKeysRequest,
) (*v1.ListPreAuthKeysResponse, error) {
	user, err := api.h.db.GetUserByID(types.UserID(request.GetUser()))
	if err != nil {
		return nil, err
	}

	preAuthKeys, err := api.h.db.ListPreAuthKeys(types.UserID(user.ID))
	if err != nil {
		return nil, err
	}

	response := make([]*v1.PreAuthKey, len(preAuthKeys))
	for index, key := range preAuthKeys {
		response[index] = key.Proto()
	}

	sort.Slice(response, func(i, j int) bool {
		return response[i].Id < response[j].Id
	})

	return &v1.ListPreAuthKeysResponse{PreAuthKeys: response}, nil
}

func (api headscaleV1APIServer) RegisterNode(
	ctx context.Context,
	request *v1.RegisterNodeRequest,
) (*v1.RegisterNodeResponse, error) {
	log.Trace().
		Str("user", request.GetUser()).
		Str("registration_id", request.GetKey()).
		Msg("Registering node")

	registrationId, err := types.RegistrationIDFromString(request.GetKey())
	if err != nil {
		return nil, err
	}
	_, _ = api.h.db.BackfillNodeIPs(api.h.ipAlloc)

	api.h.ipAlloc, err = db.NewIPAllocator(api.h.db, api.h.cfg.PrefixV4, api.h.cfg.PrefixV6, api.h.cfg.IPAllocation)

	ipv4, ipv6, err := api.h.ipAlloc.Next()
	if err != nil {
		return nil, err
	}

	user, err := api.h.db.GetUserByName(request.GetUser())
	if err != nil {
		return nil, fmt.Errorf("looking up user: %w", err)
	}

	node, _, err := api.h.db.HandleNodeFromAuthPath(
		registrationId,
		types.UserID(user.ID),
		nil,
		util.RegisterMethodCLI,
		[]*netip.Addr{
			ipv4,
		},

		[]*netip.Addr{
			ipv6,
		},
	)
	if err != nil {
		return nil, err
	}

	updateSent, err := nodesChangedHook(api.h.db, api.h.polMan, api.h.nodeNotifier)
	if err != nil {
		return nil, fmt.Errorf("updating resources using node: %w", err)
	}

	// This is a bit of a back and forth, but we have a bit of a chicken and egg
	// dependency here.
	// Because the way the policy manager works, we need to have the node
	// in the database, then add it to the policy manager and then we can
	// approve the route. This means we get this dance where the node is
	// first added to the database, then we add it to the policy manager via
	// nodesChangedHook and then we can auto approve the routes.
	// As that only approves the struct object, we need to save it again and
	// ensure we send an update.
	// This works, but might be another good candidate for doing some sort of
	// eventbus.
	routesChanged := policy.AutoApproveRoutes(api.h.polMan, node)
	if err := api.h.db.DB.Save(node).Error; err != nil {
		return nil, fmt.Errorf("saving auto approved routes to node: %w", err)
	}

	if !updateSent || routesChanged {
		ctx = types.NotifyCtx(context.Background(), "web-node-login", node.Hostname)
		api.h.nodeNotifier.NotifyAll(ctx, types.UpdatePeerChanged(node.ID))
	}

	return &v1.RegisterNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) GetNode(
	ctx context.Context,
	request *v1.GetNodeRequest,
) (*v1.GetNodeResponse, error) {
	node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
	if err != nil {
		return nil, err
	}

	resp := node.Proto()

	// Populate the online field based on
	// currently connected nodes.
	resp.Online = api.h.nodeNotifier.IsConnected(node.ID)

	return &v1.GetNodeResponse{Node: resp}, nil
}

func (api headscaleV1APIServer) SetTags(
	ctx context.Context,
	request *v1.SetTagsRequest,
) (*v1.SetTagsResponse, error) {
	for _, tag := range request.GetTags() {
		err := validateTag(tag)
		if err != nil {
			return nil, err
		}
	}

	node, err := db.Write(api.h.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		err := db.SetTags(tx, types.NodeID(request.GetNodeId()), request.GetTags())
		if err != nil {
			return nil, err
		}

		return db.GetNodeByID(tx, types.NodeID(request.GetNodeId()))
	})
	if err != nil {
		return &v1.SetTagsResponse{
			Node: nil,
		}, status.Error(codes.InvalidArgument, err.Error())
	}

	ctx = types.NotifyCtx(ctx, "cli-settags", node.Hostname)
	api.h.nodeNotifier.NotifyWithIgnore(ctx, types.UpdatePeerChanged(node.ID), node.ID)

	log.Trace().
		Str("node", node.Hostname).
		Strs("tags", request.GetTags()).
		Msg("Changing tags of node")

	return &v1.SetTagsResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) SetApprovedRoutes(
	ctx context.Context,
	request *v1.SetApprovedRoutesRequest,
) (*v1.SetApprovedRoutesResponse, error) {
	var routes []netip.Prefix
	for _, route := range request.GetRoutes() {
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			return nil, fmt.Errorf("parsing route: %w", err)
		}

		// If the prefix is an exit route, add both. The client expect both
		// to annotate the node as an exit node.
		if prefix == tsaddr.AllIPv4() || prefix == tsaddr.AllIPv6() {
			routes = append(routes, tsaddr.AllIPv4(), tsaddr.AllIPv6())
		} else {
			routes = append(routes, prefix)
		}
	}
	tsaddr.SortPrefixes(routes)
	routes = slices.Compact(routes)

	node, err := db.Write(api.h.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		err := db.SetApprovedRoutes(tx, types.NodeID(request.GetNodeId()), routes)
		if err != nil {
			return nil, err
		}

		return db.GetNodeByID(tx, types.NodeID(request.GetNodeId()))
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if api.h.primaryRoutes.SetRoutes(node.ID, node.SubnetRoutes()...) {
		ctx := types.NotifyCtx(ctx, "poll-primary-change", node.Hostname)
		api.h.nodeNotifier.NotifyAll(ctx, types.UpdateFull())
	} else {
		ctx = types.NotifyCtx(ctx, "cli-approveroutes", node.Hostname)
		api.h.nodeNotifier.NotifyWithIgnore(ctx, types.UpdatePeerChanged(node.ID), node.ID)
	}

	proto := node.Proto()
	proto.SubnetRoutes = util.PrefixesToString(api.h.primaryRoutes.PrimaryRoutes(node.ID))

	return &v1.SetApprovedRoutesResponse{Node: proto}, nil
}

func validateTag(tag string) error {
	if strings.Index(tag, "tag:") != 0 {
		return errors.New("tag must start with the string 'tag:'")
	}
	if strings.ToLower(tag) != tag {
		return errors.New("tag should be lowercase")
	}
	if len(strings.Fields(tag)) > 1 {
		return errors.New("tag should not contains space")
	}
	return nil
}

func (api headscaleV1APIServer) DeleteNode(
	ctx context.Context,
	request *v1.DeleteNodeRequest,
) (*v1.DeleteNodeResponse, error) {
	node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
	if err != nil {
		return nil, err
	}

	err = api.h.db.DeleteNode(node)
	if err != nil {
		return nil, err
	}

	ctx = types.NotifyCtx(ctx, "cli-deletenode", node.Hostname)
	api.h.nodeNotifier.NotifyAll(ctx, types.UpdatePeerRemoved(node.ID))

	return &v1.DeleteNodeResponse{}, nil
}

func (api headscaleV1APIServer) ExpireNode(
	ctx context.Context,
	request *v1.ExpireNodeRequest,
) (*v1.ExpireNodeResponse, error) {
	now := time.Now()

	node, err := db.Write(api.h.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		db.NodeSetExpiry(
			tx,
			types.NodeID(request.GetNodeId()),
			now,
		)

		return db.GetNodeByID(tx, types.NodeID(request.GetNodeId()))
	})
	if err != nil {
		return nil, err
	}

	ctx = types.NotifyCtx(ctx, "cli-expirenode-self", node.Hostname)
	api.h.nodeNotifier.NotifyByNodeID(
		ctx,
		types.UpdateSelf(node.ID),
		node.ID)

	ctx = types.NotifyCtx(ctx, "cli-expirenode-peers", node.Hostname)
	api.h.nodeNotifier.NotifyWithIgnore(ctx, types.UpdateExpire(node.ID, now), node.ID)

	log.Trace().
		Str("node", node.Hostname).
		Time("expiry", *node.Expiry).
		Msg("node expired")

	return &v1.ExpireNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) RenameNode(
	ctx context.Context,
	request *v1.RenameNodeRequest,
) (*v1.RenameNodeResponse, error) {
	node, err := db.Write(api.h.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		err := db.RenameNode(
			tx,
			types.NodeID(request.GetNodeId()),
			request.GetNewName(),
		)
		if err != nil {
			return nil, err
		}

		return db.GetNodeByID(tx, types.NodeID(request.GetNodeId()))
	})
	if err != nil {
		return nil, err
	}

	ctx = types.NotifyCtx(ctx, "cli-renamenode", node.Hostname)
	api.h.nodeNotifier.NotifyWithIgnore(ctx, types.UpdatePeerChanged(node.ID), node.ID)

	log.Trace().
		Str("node", node.Hostname).
		Str("new_name", request.GetNewName()).
		Msg("node renamed")

	return &v1.RenameNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) SyncNode(
	ctx context.Context,
	request *v1.SyncNodeRequest,
) (*v1.SyncNodeResponse, error) {

	node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
	if err != nil {
		return nil, err
	}

	ctx = types.NotifyCtx(context.Background(), "node updated", node.Hostname)
	api.h.nodeNotifier.NotifyByNodeID(ctx, types.UpdatePeerChanged(node.ID), node.ID)
	return &v1.SyncNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) AddNodeIp(
	ctx context.Context,
	request *v1.AddNodeIpRequest,
) (*v1.AddNodeIpResponse, error) {

	node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
	if err != nil {
		return nil, err
	}

	ctx = types.NotifyCtx(context.Background(), "node updated", node.Hostname)
	ip, err := netip.ParseAddr(request.GetIpAddress())
	if err != nil {
		return nil, fmt.Errorf("parsing address: %w", err)
	}
	api.h.ipAlloc, err = db.NewIPAllocator(api.h.db, api.h.cfg.PrefixV4, api.h.cfg.PrefixV6, api.h.cfg.IPAllocation)
	if ip.Is4() {
		node.IPv4s = append(node.IPv4s, &ip)
	} else {
		node.IPv6s = append(node.IPv6s, &ip)
	}
	// TODO: error handling
	_ = db.NodeSave(api.h.db.DB, node)
	fmt.Println("node.IPv4s", node.IPv4s)
	api.h.nodeNotifier.NotifyByNodeID(ctx, types.UpdatePeerChanged(node.ID), node.ID)
	return &v1.AddNodeIpResponse{Node: node.Proto()}, nil
}

// DeleteNodeIp removes an IPv4 or IPv6 address from the given node.
func (api headscaleV1APIServer) DeleteNodeIp(
	ctx context.Context,
	req *v1.DeleteNodeIpRequest,
) (*v1.DeleteNodeIpResponse, error) {

	// 1. 读取节点
	node, err := api.h.db.GetNodeByID(types.NodeID(req.GetNodeId()))
	if err != nil {
		return nil, err
	}

	// 2. 解析 IP
	ip, err := netip.ParseAddr(req.GetIpAddress())
	if err != nil {
		return nil, fmt.Errorf("parsing address: %w", err)
	}

	// 3. 在对应切片中过滤
	var (
		removed bool
		v4s     []*netip.Addr
		v6s     []*netip.Addr
	)
	if ip.Is4() {
		for _, p := range node.IPv4s {
			if p != nil && *p == ip {
				removed = true
				continue
			}
			v4s = append(v4s, p)
		}
		if !removed {
			return nil, status.Error(codes.NotFound, "ip not found on node")
		}
		node.IPv4s = v4s
	} else {
		for _, p := range node.IPv6s {
			if p != nil && *p == ip {
				removed = true
				continue
			}
			v6s = append(v6s, p)
		}
		if !removed {
			return nil, status.Error(codes.NotFound, "ip not found on node")
		}
		node.IPv6s = v6s
	}

	// 4. 保存并通知
	_ = db.NodeSave(api.h.db.DB, node) // TODO: handle error
	ctx = types.NotifyCtx(context.Background(), "node updated", node.Hostname)
	api.h.nodeNotifier.NotifyByNodeID(ctx, types.UpdatePeerChanged(node.ID), node.ID)

	// 5. 返回
	return &v1.DeleteNodeIpResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) ListNodes(
	ctx context.Context,
	request *v1.ListNodesRequest,
) (*v1.ListNodesResponse, error) {
	// TODO(kradalby): it looks like this can be simplified a lot,
	// the filtering of nodes by user, vs nodes as a whole can
	// probably be done once.
	// TODO(kradalby): This should be done in one tx.

	isLikelyConnected := api.h.nodeNotifier.LikelyConnectedMap()
	if request.GetUser() != "" {
		user, err := api.h.db.GetUserByName(request.GetUser())
		if err != nil {
			return nil, err
		}

		nodes, err := db.Read(api.h.db.DB, func(rx *gorm.DB) (types.Nodes, error) {
			return db.ListNodesByUser(rx, types.UserID(user.ID))
		})
		if err != nil {
			return nil, err
		}

		response := nodesToProto(api.h.polMan, isLikelyConnected, api.h.primaryRoutes, nodes)
		return &v1.ListNodesResponse{Nodes: response}, nil
	}

	nodes, err := api.h.db.ListNodes()
	if err != nil {
		return nil, err
	}

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})

	response := nodesToProto(api.h.polMan, isLikelyConnected, api.h.primaryRoutes, nodes)
	return &v1.ListNodesResponse{Nodes: response}, nil
}

func nodesToProto(polMan policy.PolicyManager, isLikelyConnected *xsync.MapOf[types.NodeID, bool], pr *routes.PrimaryRoutes, nodes types.Nodes) []*v1.Node {
	response := make([]*v1.Node, len(nodes))
	for index, node := range nodes {
		resp := node.Proto()

		// Populate the online field based on
		// currently connected nodes.
		if val, ok := isLikelyConnected.Load(node.ID); ok && val {
			resp.Online = true
		}

		var tags []string
		for _, tag := range node.RequestTags() {
			if polMan.NodeCanHaveTag(node, tag) {
				tags = append(tags, tag)
			}
		}
		resp.ValidTags = lo.Uniq(append(tags, node.ForcedTags...))
		resp.SubnetRoutes = util.PrefixesToString(append(pr.PrimaryRoutes(node.ID), node.ExitRoutes()...))
		response[index] = resp
	}

	return response
}

func (api headscaleV1APIServer) MoveNode(
	ctx context.Context,
	request *v1.MoveNodeRequest,
) (*v1.MoveNodeResponse, error) {
	node, err := db.Write(api.h.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		node, err := db.GetNodeByID(tx, types.NodeID(request.GetNodeId()))
		if err != nil {
			return nil, err
		}

		err = db.AssignNodeToUser(tx, node, types.UserID(request.GetUser()))
		if err != nil {
			return nil, err
		}

		return node, nil
	})
	if err != nil {
		return nil, err
	}

	ctx = types.NotifyCtx(ctx, "cli-movenode-self", node.Hostname)
	api.h.nodeNotifier.NotifyByNodeID(
		ctx,
		types.UpdateSelf(node.ID),
		node.ID)
	ctx = types.NotifyCtx(ctx, "cli-movenode", node.Hostname)
	api.h.nodeNotifier.NotifyWithIgnore(ctx, types.UpdatePeerChanged(node.ID), node.ID)

	return &v1.MoveNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) BackfillNodeIPs(
	ctx context.Context,
	request *v1.BackfillNodeIPsRequest,
) (*v1.BackfillNodeIPsResponse, error) {
	log.Trace().Msg("Backfill called")

	if !request.Confirmed {
		return nil, errors.New("not confirmed, aborting")
	}

	changes, err := api.h.db.BackfillNodeIPs(api.h.ipAlloc)
	if err != nil {
		return nil, err
	}

	return &v1.BackfillNodeIPsResponse{Changes: changes}, nil
}

func (api headscaleV1APIServer) CreateApiKey(
	ctx context.Context,
	request *v1.CreateApiKeyRequest,
) (*v1.CreateApiKeyResponse, error) {
	var expiration time.Time
	if request.GetExpiration() != nil {
		expiration = request.GetExpiration().AsTime()
	}

	apiKey, _, err := api.h.db.CreateAPIKey(
		&expiration,
	)
	if err != nil {
		return nil, err
	}

	return &v1.CreateApiKeyResponse{ApiKey: apiKey}, nil
}

func (api headscaleV1APIServer) ExpireApiKey(
	ctx context.Context,
	request *v1.ExpireApiKeyRequest,
) (*v1.ExpireApiKeyResponse, error) {
	var apiKey *types.APIKey
	var err error

	apiKey, err = api.h.db.GetAPIKey(request.Prefix)
	if err != nil {
		return nil, err
	}

	err = api.h.db.ExpireAPIKey(apiKey)
	if err != nil {
		return nil, err
	}

	return &v1.ExpireApiKeyResponse{}, nil
}

func (api headscaleV1APIServer) ListApiKeys(
	ctx context.Context,
	request *v1.ListApiKeysRequest,
) (*v1.ListApiKeysResponse, error) {
	apiKeys, err := api.h.db.ListAPIKeys()
	if err != nil {
		return nil, err
	}

	response := make([]*v1.ApiKey, len(apiKeys))
	for index, key := range apiKeys {
		response[index] = key.Proto()
	}

	sort.Slice(response, func(i, j int) bool {
		return response[i].Id < response[j].Id
	})

	return &v1.ListApiKeysResponse{ApiKeys: response}, nil
}

func (api headscaleV1APIServer) DeleteApiKey(
	ctx context.Context,
	request *v1.DeleteApiKeyRequest,
) (*v1.DeleteApiKeyResponse, error) {
	var (
		apiKey *types.APIKey
		err    error
	)

	apiKey, err = api.h.db.GetAPIKey(request.Prefix)
	if err != nil {
		return nil, err
	}

	if err := api.h.db.DestroyAPIKey(*apiKey); err != nil {
		return nil, err
	}

	return &v1.DeleteApiKeyResponse{}, nil
}

func (api headscaleV1APIServer) GetPolicy(
	_ context.Context,
	_ *v1.GetPolicyRequest,
) (*v1.GetPolicyResponse, error) {
	switch api.h.cfg.Policy.Mode {
	case types.PolicyModeDB:
		p, err := api.h.db.GetPolicy()
		if err != nil {
			return nil, fmt.Errorf("loading ACL from database: %w", err)
		}

		return &v1.GetPolicyResponse{
			Policy:    p.Data,
			UpdatedAt: timestamppb.New(p.UpdatedAt),
		}, nil
	case types.PolicyModeFile:
		// Read the file and return the contents as-is.
		absPath := util.AbsolutePathFromConfigPath(api.h.cfg.Policy.Path)
		f, err := os.Open(absPath)
		if err != nil {
			return nil, fmt.Errorf("reading policy from path %q: %w", absPath, err)
		}

		defer f.Close()

		b, err := io.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("reading policy from file: %w", err)
		}

		return &v1.GetPolicyResponse{Policy: string(b)}, nil
	}

	return nil, fmt.Errorf("no supported policy mode found in configuration, policy.mode: %q", api.h.cfg.Policy.Mode)
}

func (api headscaleV1APIServer) SetPolicy(
	_ context.Context,
	request *v1.SetPolicyRequest,
) (*v1.SetPolicyResponse, error) {
	if api.h.cfg.Policy.Mode != types.PolicyModeDB {
		return nil, types.ErrPolicyUpdateIsDisabled
	}

	p := request.GetPolicy()

	// Validate and reject configuration that would error when applied
	// when creating a map response. This requires nodes, so there is still
	// a scenario where they might be allowed if the server has no nodes
	// yet, but it should help for the general case and for hot reloading
	// configurations.
	nodes, err := api.h.db.ListNodes()
	if err != nil {
		return nil, fmt.Errorf("loading nodes from database to validate policy: %w", err)
	}
	changed, err := api.h.polMan.SetPolicy([]byte(p))
	if err != nil {
		return nil, fmt.Errorf("setting policy: %w", err)
	}

	if len(nodes) > 0 {
		_, err = api.h.polMan.SSHPolicy(nodes[0])
		if err != nil {
			return nil, fmt.Errorf("verifying SSH rules: %w", err)
		}
	}

	updated, err := api.h.db.SetPolicy(p)
	if err != nil {
		return nil, err
	}

	// Only send update if the packet filter has changed.
	if changed {
		err = api.h.autoApproveNodes()
		if err != nil {
			return nil, err
		}

		ctx := types.NotifyCtx(context.Background(), "acl-update", "na")
		api.h.nodeNotifier.NotifyAll(ctx, types.UpdateFull())
	}

	response := &v1.SetPolicyResponse{
		Policy:    updated.Data,
		UpdatedAt: timestamppb.New(updated.UpdatedAt),
	}

	return response, nil
}

// The following service calls are for testing and debugging
func (api headscaleV1APIServer) DebugCreateNode(
	ctx context.Context,
	request *v1.DebugCreateNodeRequest,
) (*v1.DebugCreateNodeResponse, error) {
	user, err := api.h.db.GetUserByName(request.GetUser())
	if err != nil {
		return nil, err
	}

	routes, err := util.StringToIPPrefix(request.GetRoutes())
	if err != nil {
		return nil, err
	}

	log.Trace().
		Caller().
		Interface("route-prefix", routes).
		Interface("route-str", request.GetRoutes()).
		Msg("")

	hostinfo := tailcfg.Hostinfo{
		RoutableIPs: routes,
		OS:          "TestOS",
		Hostname:    "DebugTestNode",
	}

	registrationId, err := types.RegistrationIDFromString(request.GetKey())
	if err != nil {
		return nil, err
	}

	newNode := types.RegisterNode{
		Node: types.Node{
			NodeKey:    key.NewNode().Public(),
			MachineKey: key.NewMachine().Public(),
			Hostname:   request.GetName(),
			User:       *user,

			Expiry:   &time.Time{},
			LastSeen: &time.Time{},

			Hostinfo: &hostinfo,
		},
		Registered: make(chan *types.Node),
	}

	log.Debug().
		Str("registration_id", registrationId.String()).
		Msg("adding debug machine via CLI, appending to registration cache")

	api.h.registrationCache.Set(
		registrationId,
		newNode,
	)

	return &v1.DebugCreateNodeResponse{Node: newNode.Node.Proto()}, nil
}

func (api headscaleV1APIServer) mustEmbedUnimplementedHeadscaleServiceServer() {}
