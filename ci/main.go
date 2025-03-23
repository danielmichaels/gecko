package main

import (
	"context"
	"dagger/gecko/internal/dagger"
	"fmt"
)

type Backend struct{}

func (m *Backend) Lint(ctx context.Context, src *dagger.Directory) (string, error) {
	return dag.Container().
		From("danielmichaels/ci-toolkit").
		WithDirectory("/src", src).
		WithWorkdir("/src").
		WithExec([]string{"task", "betteralign"}, dagger.ContainerWithExecOpts{}).
		WithExec([]string{"task", "golines-ci"}, dagger.ContainerWithExecOpts{}).
		WithExec([]string{"task", "golangci"}, dagger.ContainerWithExecOpts{}).
		Stdout(ctx)
}
func (m *Backend) Test(ctx context.Context, src *dagger.Directory) (string, error) {
	if _, err := dag.Testcontainers().DockerService().Start(ctx); err != nil {
		return "", err
	}
	pg := dag.Container().
		From("postgres:16-alpine").
		WithEnvVariable("POSTGRES_PASSWORD", "postgres").
		WithEnvVariable("POSTGRES_USER", "postgres").
		WithEnvVariable("POSTGRES_DB", "test-db").
		With(dag.Testcontainers().Setup).
		AsService(dagger.ContainerAsServiceOpts{UseEntrypoint: true})
	svc := dag.Container().
		From("danielmichaels/ci-toolkit").
		WithDirectory("/src", src).
		With(dag.Testcontainers().Setup).
		WithWorkdir("/src")
	return svc.
		WithServiceBinding("db", pg).
		WithEnvVariable("POSTGRES_DB", "test-db").
		WithEnvVariable("POSTGRES_USER", "postgres").
		WithEnvVariable("POSTGRES_PASSWORD", "postgres").
		WithWorkdir("/src").
		WithExec([]string{"go", "build", "-v", "./..."}, dagger.ContainerWithExecOpts{}).
		WithExec([]string{"go", "test", "-v", "-race", "./..."}, dagger.ContainerWithExecOpts{}).
		With(dag.Testcontainers().Setup).
		Stdout(ctx)

}

func (m *Backend) Build(
	ctx context.Context,
	src *dagger.Directory,
	dockerfile *dagger.File,
) (*dagger.Container, error) {
	workspace := dag.Container().
		WithDirectory(".", src).
		WithWorkdir(".").
		WithFile("./Dockerfile", dockerfile).
		Directory(".")
	ref := dag.Container().
		Build(workspace, dagger.ContainerBuildOpts{
			Dockerfile: "Dockerfile",
		})
	return ref, nil
}

func (m *Backend) LintTestBuild(
	ctx context.Context,
	src *dagger.Directory,
	dockerfile *dagger.File,
) (*dagger.Container, error) {
	_, err := m.Lint(ctx, src)
	if err != nil {
		return nil, err
	}
	_, err = m.Test(ctx, src)
	if err != nil {
		return nil, err
	}
	return m.Build(ctx, src, dockerfile)
}

func (m *Backend) Publish(
	ctx context.Context,
	buildContext *dagger.Directory,
	dockerfile *dagger.File,
	registry, imageName, registryUsername string,
	registryPassword *dagger.Secret,
	tags []string,
) ([]string, error) {
	var addr []string
	b, err := m.Build(ctx, buildContext, dockerfile)
	if err != nil {
		return addr, err
	}
	ctr := b.WithRegistryAuth(registry, registryUsername, registryPassword)
	for _, tag := range tags {
		a, err := ctr.Publish(ctx, fmt.Sprintf("%s/%s:%s", registry, imageName, tag))
		if err != nil {
			return addr, err
		}
		addr = append(addr, a)
	}
	return addr, err
}
