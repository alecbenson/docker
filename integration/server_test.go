package docker

import (
	"bytes"
	"testing"

	"github.com/docker/docker/builder"
	"github.com/docker/docker/engine"
	"github.com/docker/docker/registry"
)

func TestCreateNumberHostname(t *testing.T) {
	eng := NewTestEngine(t)
	defer mkDaemonFromEngine(eng, t).Nuke()

	config, _, _, err := parseRun([]string{"-h", "web.0", unitTestImageID, "echo test"})
	if err != nil {
		t.Fatal(err)
	}

	createTestContainer(eng, config, t)
}

func TestRunWithTooLowMemoryLimit(t *testing.T) {
	eng := NewTestEngine(t)
	defer mkDaemonFromEngine(eng, t).Nuke()

	// Try to create a container with a memory limit of 1 byte less than the minimum allowed limit.
	job := eng.Job("create")
	job.Setenv("Image", unitTestImageID)
	job.Setenv("Memory", "524287")
	job.Setenv("CpuShares", "1000")
	job.SetenvList("Cmd", []string{"/bin/cat"})
	if err := job.Run(); err == nil {
		t.Errorf("Memory limit is smaller than the allowed limit. Container creation should've failed!")
	}
}

func TestImagesFilter(t *testing.T) {
	eng := NewTestEngine(t)
	defer nuke(mkDaemonFromEngine(eng, t))

	if err := eng.Job("tag", unitTestImageName, "utest", "tag1").Run(); err != nil {
		t.Fatal(err)
	}

	if err := eng.Job("tag", unitTestImageName, "utest/docker", "tag2").Run(); err != nil {
		t.Fatal(err)
	}

	if err := eng.Job("tag", unitTestImageName, "utest:5000/docker", "tag3").Run(); err != nil {
		t.Fatal(err)
	}

	images := getImages(eng, t, false, "*utest*/*")
	repoTags := images.Data[0].GetList("RepoTags")
	if len(images[0].Data[0].GetList("RepoTags")) != 1 {
		t.Fatal("incorrect number of matches returned")
	}
	expected := "utest:5000/docker:tag3"
	if repoTags[0] != expected {
		t.Fatal("got unexpected repo tag (%s != %s)", repoTags[0], "utest:5000/docker:tag3")
	}

	images = getImages(eng, t, false, registry.INDEXNAME+"/utest*/*")
	repoTags = images[0].Data[0].GetList("RepoTags")
	if len(repoTags) != 2 {
		t.Fatal("incorrect number of matches returned")
	}
	expected = registry.INDEXNAME + "/utest/docker:tag2"
	if repoTags[0] != expected {
		t.Fatal("got unexpected repo tag (%s != %s)", repoTags[0], expected)
	}

	images = getImages(eng, t, false, registry.INDEXNAME+"/*test*")
	if len(images[0].Data[0].GetList("RepoTags")) != 2 {
		t.Fatal("incorrect number of matches returned")
	}

	images = getImages(eng, t, false, registry.INDEXNAME+"/utest")
	if len(images[0].Data[0].GetList("RepoTags")) != 1 {
		t.Fatal("incorrect number of matches returned")
	}

	images = getImages(eng, t, false, registry.INDEXNAME+"/utest*")
	if len(images[0].Data[0].GetList("RepoTags")) != 1 {
		t.Fatal("incorrect number of matches returned")
	}

	images = getImages(eng, t, false, "*5000*/*")
	if len(images[0].Data[0].GetList("RepoTags")) != 1 {
		t.Fatal("incorrect number of matches returned")
	}
}
