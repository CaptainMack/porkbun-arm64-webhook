package porkbun

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/nrdcg/porkbun"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	klog "k8s.io/klog/v2"
)

type PorkbunSolver struct {
	kube kubernetes.Interface
	// baseURL overrides the Porkbun API endpoint; nil means the real API. Tests only.
	baseURL *url.URL
}

func (e *PorkbunSolver) Name() string {
	return "porkbun"
}

type Config struct {
	ApiKeySecretRef    corev1.SecretKeySelector `json:"apiKeySecretRef"`
	SecretKeySecretRef corev1.SecretKeySelector `json:"secretKeySecretRef"`
}

func (e *PorkbunSolver) readConfig(request *acme.ChallengeRequest) (*porkbun.Client, error) {
	config := Config{}

	if request.Config != nil {
		if err := json.Unmarshal(request.Config.Raw, &config); err != nil {
			return nil, fmt.Errorf("config error: %w", err)
		}
	}

	apiKey, err := e.resolveSecretRef(config.ApiKeySecretRef, request)
	if err != nil {
		return nil, err
	}

	secretKey, err := e.resolveSecretRef(config.SecretKeySecretRef, request)
	if err != nil {
		return nil, err
	}

	client := porkbun.New(secretKey, apiKey)
	if e.baseURL != nil {
		client.BaseURL = e.baseURL
	}
	return client, nil
}

func (e *PorkbunSolver) resolveSecretRef(selector corev1.SecretKeySelector, ch *acme.ChallengeRequest) (string, error) {
	secret, err := e.kube.CoreV1().Secrets(ch.ResourceNamespace).Get(context.Background(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get error for secret %q %q: %w", ch.ResourceNamespace, selector.Name, err)
	}

	bytes, ok := secret.Data[selector.Key]
	if !ok {
		return "", fmt.Errorf("secret %q %q does not contain key %q", ch.ResourceNamespace, selector.Name, selector.Key)
	}

	return string(bytes), nil
}

// recordNames splits the challenge into the Porkbun domain, the record's
// subdomain part ("entity") and its full name, refusing names outside the zone
// so a malformed request can never touch records elsewhere.
func recordNames(ch *acme.ChallengeRequest) (domain, entity, name string, err error) {
	domain = strings.TrimSuffix(ch.ResolvedZone, ".")
	name = strings.TrimSuffix(ch.ResolvedFQDN, ".")
	if domain == "" || !strings.HasSuffix(name, "."+domain) {
		return "", "", "", fmt.Errorf("FQDN %q is not inside zone %q", ch.ResolvedFQDN, ch.ResolvedZone)
	}
	entity = strings.TrimSuffix(name, "."+domain)
	return domain, entity, name, nil
}

func (e *PorkbunSolver) Present(ch *acme.ChallengeRequest) error {
	klog.Infof("Handling present request for %q %q", ch.ResolvedFQDN, ch.Key)

	domain, entity, name, err := recordNames(ch)
	if err != nil {
		return err
	}

	client, err := e.readConfig(ch)
	if err != nil {
		return fmt.Errorf("initialization error: %w", err)
	}

	records, err := client.RetrieveRecords(context.Background(), domain)
	if err != nil {
		return fmt.Errorf("retrieve records error: %w", err)
	}

	for _, record := range records {
		if record.Type == "TXT" && record.Name == name && record.Content == ch.Key {
			klog.Infof("Record %s is already present", record.ID)
			return nil
		}
	}

	id, err := client.CreateRecord(context.Background(), domain, porkbun.Record{
		Name:    entity,
		Type:    "TXT",
		Content: ch.Key,
		TTL:     porkbun.DefaultTTL, // Porkbun rejects anything below its 300s minimum
	})
	if err != nil {
		return fmt.Errorf("create record error: %w", err)
	}

	klog.Infof("Created record %v", id)
	return nil
}

func (e *PorkbunSolver) CleanUp(ch *acme.ChallengeRequest) error {
	klog.Infof("Handling cleanup request for %q %q", ch.ResolvedFQDN, ch.Key)

	domain, _, name, err := recordNames(ch)
	if err != nil {
		return err
	}

	client, err := e.readConfig(ch)
	if err != nil {
		return fmt.Errorf("initialization error: %w", err)
	}

	records, err := client.RetrieveRecords(context.Background(), domain)
	if err != nil {
		return fmt.Errorf("retrieve records error: %w", err)
	}

	// Only ever delete the exact TXT record this challenge created.
	for _, record := range records {
		if record.Type == "TXT" && record.Name == name && record.Content == ch.Key {
			// Atoi parses into the platform int (64-bit on our targets; record IDs
			// outgrow int32) and errors instead of truncating on overflow.
			id, err := strconv.Atoi(record.ID)
			if err != nil {
				return fmt.Errorf("found TXT record, but its ID %q is malformed: %w", record.ID, err)
			}

			if err := client.DeleteRecord(context.Background(), domain, id); err != nil {
				return fmt.Errorf("delete record error: %w", err)
			}

			klog.Infof("Deleted record %v", id)
			return nil
		}
	}

	klog.Info("No matching record to delete")

	return nil
}

func (e *PorkbunSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	klog.Info("Initializing")

	kube, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("kube client creation error: %w", err)
	}

	e.kube = kube
	return nil
}

func New() webhook.Solver {
	return &PorkbunSolver{}
}
