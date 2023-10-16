package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/Nerzal/gocloak/v13"
)

type GocloakWrapper interface {
	GetClient(ctx context.Context, clientId string) (*gocloak.Client, error)
	UpdateClient(ctx context.Context, client gocloak.Client) error
}

type DefaultGocloakWrapper struct {
	GoCloak      gocloak.GoCloak
	Token        *gocloak.JWT
	ClientId     string
	ClientSecret string
	Realm        string
	TokenExpiry  int
}

var _ GocloakWrapper = &DefaultGocloakWrapper{}

func (k *DefaultGocloakWrapper) GetClient(ctx context.Context, clientId string) (*gocloak.Client, error) {
	// Ensure we are authenticated with Keycloak
	if err := k.ensureToken(ctx); err != nil {
		return nil, err
	}

	return k.getClientFromId(ctx, clientId)
}

func (k *DefaultGocloakWrapper) UpdateClient(ctx context.Context, client gocloak.Client) error {
	// Ensure we are authenticated with Keycloak
	if err := k.ensureToken(ctx); err != nil {
		return err
	}

	// Update client
	if err := k.GoCloak.UpdateClient(ctx, k.Token.AccessToken, k.Realm, client); err != nil {
		return err
	}

	return nil
}

func (k *DefaultGocloakWrapper) ensureToken(ctx context.Context) error {
	if k.Token == nil {
		token, err := k.GoCloak.LoginClient(ctx, k.ClientId, k.ClientSecret, k.Realm)
		if err != nil {
			return err
		}
		k.Token = token

		retrospect, err := k.GoCloak.RetrospectToken(ctx, token.AccessToken, k.ClientId, k.ClientSecret, k.Realm)
		if err != nil {
			return err
		}
		if !*retrospect.Active {
			return fmt.Errorf("token is not active")
		}
		k.TokenExpiry = *retrospect.Exp
		return nil
	}

	// If token is about to expire, get a new one
	if time.Now().UTC().Unix()+600 > int64(k.TokenExpiry) {
		k.Token = nil
		return k.ensureToken(ctx)
	}

	return nil
}

func (k *DefaultGocloakWrapper) getClientFromId(ctx context.Context, clientId string) (*gocloak.Client, error) {
	// Get all clients in realm matching filter (should only be one)
	// Gocloak has no way of getting a single client by id (only by internal id)
	clients, err := k.GoCloak.GetClients(ctx, k.Token.AccessToken, k.Realm, gocloak.GetClientsParams{
		ClientID: &clientId,
	})
	if err != nil {
		return nil, err
	}

	// Clients should only contain one client, which is the one we want
	for _, client := range clients {
		return client, nil
	}

	// If clients is empty, the client does not exist
	return nil, fmt.Errorf("client with id %s not found", clientId)
}
