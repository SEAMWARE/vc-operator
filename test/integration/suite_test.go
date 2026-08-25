//go:build integration

/*
Copyright 2026 Seamless Middleware Technologies S.L and/or its affiliates
and other contributors as indicated by the @author tags.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package integration contains end-to-end integration tests for the vc-operator.
// These tests verify the full credential lifecycle by running both controllers
// (CredentialIssuer and VerifiableCredentialRequest) against an envtest-based
// Kubernetes API server and a mock OID4VCI issuer that simulates Keycloak's
// OID4VCI endpoints.
//
// The tests are gated behind the "integration" build tag and can be run with:
//
//	make test-integration
//
// or directly:
//
//	go test -tags=integration ./test/integration/ -v
package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	vcv1alpha1 "github.com/SEAMWARE/vc-operator/api/v1alpha1"
	"github.com/SEAMWARE/vc-operator/internal/controller"
	kubestore "github.com/SEAMWARE/vc-operator/internal/credentialstore/kubernetes"
	"github.com/SEAMWARE/vc-operator/internal/oid4vci"
)

// Package-level test infrastructure shared across all integration tests.
var (
	// ctx is the test-scoped context, cancelled in AfterSuite.
	ctx context.Context

	// cancel cancels the test context, stopping the controller manager.
	cancel context.CancelFunc

	// testEnv is the envtest Kubernetes API server environment.
	testEnv *envtest.Environment

	// cfg is the rest.Config for connecting to the envtest API server.
	cfg *rest.Config

	// k8sClient is the controller-runtime client for test assertions.
	k8sClient client.Client

	// testScheme is the runtime scheme with all required types registered.
	testScheme *runtime.Scheme

	// mockIssuer is the mock OID4VCI issuer simulating Keycloak.
	mockIssuer *MockOID4VCIIssuer
)

// TestIntegration is the Ginkgo test runner entry point for the
// integration test suite. It registers Ginkgo's fail handler and
// runs all specs in this package.
func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting vc-operator integration test suite\n")
	RunSpecs(t, "Integration Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	// Register all types in the scheme.
	testScheme = runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(testScheme))
	utilruntime.Must(vcv1alpha1.AddToScheme(testScheme))

	// Start the mock OID4VCI issuer (simulates Keycloak with OID4VCI support).
	By("starting mock OID4VCI issuer (Keycloak simulation)")
	mockIssuer = NewMockOID4VCIIssuer()
	_, _ = fmt.Fprintf(GinkgoWriter, "Mock OID4VCI issuer started at %s\n", mockIssuer.URL())

	// Bootstrap the envtest Kubernetes API server.
	By("bootstrapping envtest environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	// Auto-detect envtest binary directory for IDE compatibility.
	if dir := getFirstFoundEnvTestBinaryDir(); dir != "" {
		testEnv.BinaryAssetsDirectory = dir
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred(), "Failed to start envtest")
	Expect(cfg).NotTo(BeNil())

	// Create the k8s client for test assertions.
	k8sClient, err = client.New(cfg, client.Options{Scheme: testScheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	// Create and configure the controller manager.
	By("creating controller manager with mock OID4VCI client")
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: testScheme,
		Metrics: metricsserver.Options{
			BindAddress: "0", // Disable metrics server in tests.
		},
		HealthProbeBindAddress: "0", // Disable health probes in tests.
	})
	Expect(err).NotTo(HaveOccurred(), "Failed to create manager")

	// Create the OID4VCI client (real client talking to mock server).
	oid4vciClient := oid4vci.NewClient()

	// Register the CredentialIssuer controller.
	err = (&controller.CredentialIssuerReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		OID4VCIClient: oid4vciClient,
		EventRecorder: mgr.GetEventRecorderFor("credentialissuer-controller"),
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred(), "Failed to set up CredentialIssuer controller")

	// Register the VerifiableCredentialRequest controller.
	// Metrics are intentionally nil to avoid duplicate Prometheus registration.
	err = (&controller.VerifiableCredentialRequestReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		OID4VCIClient:   oid4vciClient,
		CredentialStore: kubestore.NewSecretStore(mgr.GetClient()),
		EventRecorder:   mgr.GetEventRecorderFor("vcrequest-controller"),
		Clock:           controller.RealClock{},
		Metrics:         nil, // Metrics disabled in integration tests.
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred(), "Failed to set up VerifiableCredentialRequest controller")

	// Start the controller manager in a background goroutine.
	By("starting controller manager")
	go func() {
		defer GinkgoRecover()
		err := mgr.Start(ctx)
		Expect(err).NotTo(HaveOccurred(), "Controller manager exited with error")
	}()

	_, _ = fmt.Fprintf(GinkgoWriter, "Integration test suite setup complete\n")
})

var _ = AfterSuite(func() {
	By("tearing down integration test environment")

	// Cancel the context to stop the controller manager.
	cancel()

	// Stop the mock OID4VCI issuer.
	if mockIssuer != nil {
		mockIssuer.Stop()
	}

	// Stop the envtest environment.
	Eventually(func() error {
		return testEnv.Stop()
	}, time.Minute, time.Second).Should(Succeed(), "Failed to stop envtest")
})

// getFirstFoundEnvTestBinaryDir locates the first binary directory in the
// bin/k8s path. ENVTEST-based tests depend on specific binaries usually
// set up by 'make setup-envtest'. This function enables running tests
// directly from an IDE without setting KUBEBUILDER_ASSETS explicitly.
func getFirstFoundEnvTestBinaryDir() string {
	basePath := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(basePath)
	if err != nil {
		logf.Log.V(1).Info("Could not read envtest binary directory", "path", basePath, "error", err)
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(basePath, entry.Name())
		}
	}
	return ""
}
