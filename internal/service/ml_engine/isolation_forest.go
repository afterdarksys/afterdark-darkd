package ml_engine

import (
	"math"
	"math/rand"
	"sync"
)

// AnomalyDetector defines the interface for anomaly detection models
type AnomalyDetector interface {
	Train(data [][]float64) error
	Score(sample []float64) float64
}

// IsolationForest is a simplified implementation of the Isolation Forest algorithm
// suitable for real-time anomaly detection on endpoints.
type IsolationForest struct {
	Trees     []*iTree
	NumTrees  int
	Subsample int
	Height    int
	mu        sync.RWMutex
}

type iTree struct {
	Root *iNode
}

type iNode struct {
	Feature   int
	Threshold float64
	Left      *iNode
	Right     *iNode
	Size      int
	IsLeaf    bool
}

// NewIsolationForest creates a new model
func NewIsolationForest(numTrees, subsample int) *IsolationForest {
	return &IsolationForest{
		NumTrees:  numTrees,
		Subsample: subsample,
		Height:    int(math.Ceil(math.Log2(float64(subsample)))),
	}
}

// Train trains the model with the provided data
func (f *IsolationForest) Train(data [][]float64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.Trees = make([]*iTree, 0, f.NumTrees)

	for i := 0; i < f.NumTrees; i++ {
		// Subsample
		sample := make([][]float64, 0, f.Subsample)
		for j := 0; j < f.Subsample; j++ {
			if len(data) > 0 {
				idx := rand.Intn(len(data))
				sample = append(sample, data[idx])
			}
		}

		if len(sample) == 0 {
			continue
		}

		tree := &iTree{
			Root: f.buildTree(sample, 0, f.Height),
		}
		f.Trees = append(f.Trees, tree)
	}

	return nil
}

func (f *IsolationForest) buildTree(data [][]float64, depth, limit int) *iNode {
	if depth >= limit || len(data) <= 1 {
		return &iNode{Size: len(data), IsLeaf: true}
	}

	// Randomly select feature and threshold
	numFeatures := len(data[0])
	feature := rand.Intn(numFeatures)

	// Find min/max for this feature
	minVal, maxVal := data[0][feature], data[0][feature]
	for _, row := range data {
		val := row[feature]
		if val < minVal {
			minVal = val
		}
		if val > maxVal {
			maxVal = val
		}
	}

	if minVal == maxVal {
		return &iNode{Size: len(data), IsLeaf: true}
	}

	threshold := minVal + rand.Float64()*(maxVal-minVal)

	// Split data
	var left, right [][]float64
	for _, row := range data {
		if row[feature] < threshold {
			left = append(left, row)
		} else {
			right = append(right, row)
		}
	}

	return &iNode{
		Feature:   feature,
		Threshold: threshold,
		Left:      f.buildTree(left, depth+1, limit),
		Right:     f.buildTree(right, depth+1, limit),
		IsLeaf:    false,
		Size:      len(data),
	}
}

// Score calculates the anomaly score (0.0 normal, 1.0 anomaly)
func (f *IsolationForest) Score(sample []float64) float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if len(f.Trees) == 0 {
		return 0.0
	}

	avgPathLen := 0.0
	for _, tree := range f.Trees {
		avgPathLen += pathLength(sample, tree.Root, 0)
	}
	avgPathLen /= float64(len(f.Trees))

	// Normalize
	// c(n) = 2H(n-1) - (2(n-1)/n)
	n := float64(f.Subsample)
	cn := 2.0*(math.Log(n-1)+0.57721566) - (2.0 * (n - 1) / n)

	score := math.Pow(2.0, -avgPathLen/cn)
	return score
}

func pathLength(sample []float64, node *iNode, depth int) float64 {
	if node.IsLeaf {
		return float64(depth) + c(float64(node.Size))
	}

	if sample[node.Feature] < node.Threshold {
		return pathLength(sample, node.Left, depth+1)
	}
	return pathLength(sample, node.Right, depth+1)
}

func c(n float64) float64 {
	if n <= 1 {
		return 0
	}
	return 2.0*(math.Log(n-1)+0.57721566) - (2.0 * (n - 1) / n)
}
