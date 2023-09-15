package vex

import (
	"fmt"
	"slices"

	csaf "github.com/csaf-poc/csaf_distribution/v2/csaf"
)

// urlFinder helps to find the URLs of a set of product ids in advisories.
type urlFinder struct {
	ids  []csaf.ProductID
	urls [][]csaf.PURL
}

// newURLFinder creates a new urlFinder for given ids.
func newURLFinder(products csaf.Products) *urlFinder {
	uf := &urlFinder{
		ids:  make([]csaf.ProductID, len(products)),
		urls: make([][]csaf.PURL, len(products)),
	}
	for i, product := range products {
		uf.ids[i] = *product
	}
	return uf
}

// clear resets the url finder after a run on an advisory.
func (uf *urlFinder) clear() {
	clear(uf.urls)
}

// dumpURLs dumps the found URLs to stdout.
func (uf *urlFinder) dumpURLs() {
	for i, urls := range uf.urls {
		if len(urls) == 0 {
			continue
		}
		fmt.Printf("Found URLs for %s:\n", uf.ids[i])
		for j, url := range urls {
			fmt.Printf("%d. %s\n", j+1, url)
		}
	}
}

// Returns all URLs found for all product ids
func (uf *urlFinder) getFoundURLs() []string {
	var result []string

	// Iterate through the URLs found for each Product ID
	for _, urls := range uf.urls {
		for _, url := range urls {
			result = append(result, string(url))
		}
	}

	return result
}

// findURLs find the URLs in an advisory.
func (uf *urlFinder) findURLs(adv *csaf.Advisory) {
	tree := adv.ProductTree
	if tree == nil {
		return
	}

	// If we have found it and we have a valid URL add unique.
	add := func(idx int, h *csaf.ProductIdentificationHelper) {
		if idx != -1 && h != nil && h.PURL != nil &&
			!slices.Contains(uf.urls[idx], *h.PURL) {
			uf.urls[idx] = append(uf.urls[idx], *h.PURL)
		}
	}

	// First iterate over full product names.
	if names := tree.FullProductNames; names != nil {
		for _, name := range *names {
			if name != nil && name.ProductID != nil {
				add(slices.Index(uf.ids, *name.ProductID), name.ProductIdentificationHelper)
			}
		}
	}

	// Second traverse the branches recursively.
	var recBranch func(*csaf.Branch)
	recBranch = func(b *csaf.Branch) {
		if p := b.Product; p != nil && p.ProductID != nil {
			add(slices.Index(uf.ids, *p.ProductID), p.ProductIdentificationHelper)
		}
		for _, c := range b.Branches {
			recBranch(c)
		}
	}
	for _, b := range tree.Branches {
		recBranch(b)
	}
}
