package bolt_test

import (
	"path/filepath"
	"testing"

	"github.com/boltdb/bolt"
	gc "gopkg.in/check.v1"

	sfbolt "github.com/cmars/shadowfax/storage/bolt"
	sftesting "github.com/cmars/shadowfax/testing"
)

func Test(t *testing.T) { gc.TestingT(t) }

type boltHandlerSuite struct {
	*sftesting.HTTPHandlerSuite
}

var _ = gc.Suite(&boltHandlerSuite{&sftesting.HTTPHandlerSuite{}})

func (s *boltHandlerSuite) SetUpTest(c *gc.C) {
	dir := c.MkDir()
	db, err := bolt.Open(filepath.Join(dir, "testdb"), 0600, nil)
	c.Assert(err, gc.IsNil)
	s.HTTPHandlerSuite.SetStorage(sfbolt.NewService(db))
	s.HTTPHandlerSuite.SetUpTest(c)
}

func (s *boltHandlerSuite) TearDownTest(c *gc.C) {
	s.HTTPHandlerSuite.TearDownTest(c)
}
