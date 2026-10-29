package scanner

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var ErrInvalidTemplateCategory = errors.New("invalid template category")

func resolveTemplateCategory(root, categoryPath string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve template staging root: %w", err)
	}
	categoryPath = strings.TrimSpace(strings.ReplaceAll(categoryPath, "\\", "/"))
	if categoryPath == "" {
		return root, nil
	}
	if path.IsAbs(categoryPath) {
		return "", fmt.Errorf("%w: path must be relative", ErrInvalidTemplateCategory)
	}
	for _, part := range strings.Split(categoryPath, "/") {
		if part == ".." {
			return "", fmt.Errorf("%w: parent-directory segments are not allowed", ErrInvalidTemplateCategory)
		}
	}
	categoryPath = path.Clean(categoryPath)
	if categoryPath == "." || categoryPath == ".." {
		return "", fmt.Errorf("%w: path must name a directory", ErrInvalidTemplateCategory)
	}

	selected := filepath.Join(root, filepath.FromSlash(categoryPath))
	relative, err := filepath.Rel(root, selected)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: selected directory is outside the staging root", ErrInvalidTemplateCategory)
	}
	rootResolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve template staging root: %w", err)
	}
	selectedResolved, err := filepath.EvalSymlinks(selected)
	if err != nil {
		return "", fmt.Errorf("%w: selected directory %q does not exist", ErrInvalidTemplateCategory, categoryPath)
	}
	relative, err = filepath.Rel(rootResolved, selectedResolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: selected directory resolves outside the staging root", ErrInvalidTemplateCategory)
	}
	info, err := os.Stat(selectedResolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("%w: selected path %q is not a directory", ErrInvalidTemplateCategory, categoryPath)
	}
	return selectedResolved, nil
}

func filterStagedTemplatesByCategory(staged []StagedFile, categoryPath string) ([]StagedFile, error) {
	categoryPath = strings.TrimSpace(strings.ReplaceAll(categoryPath, "\\", "/"))
	if categoryPath == "" {
		templates := make([]StagedFile, 0, len(staged))
		for _, file := range staged {
			if !file.Support {
				templates = append(templates, file)
			}
		}
		return templates, nil
	}
	if path.IsAbs(categoryPath) {
		return nil, fmt.Errorf("%w: path must be relative", ErrInvalidTemplateCategory)
	}
	for _, part := range strings.Split(categoryPath, "/") {
		if part == ".." {
			return nil, fmt.Errorf("%w: parent-directory segments are not allowed", ErrInvalidTemplateCategory)
		}
	}
	categoryPath = path.Clean(categoryPath)
	if categoryPath == "." || categoryPath == ".." {
		return nil, fmt.Errorf("%w: path must name a directory", ErrInvalidTemplateCategory)
	}

	prefix := categoryPath + "/"
	filtered := make([]StagedFile, 0)
	for _, file := range staged {
		if file.Support {
			continue
		}
		relativePath := path.Clean(strings.ReplaceAll(file.RelativePath, "\\", "/"))
		if strings.HasPrefix(relativePath, prefix) {
			filtered = append(filtered, file)
		}
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("%w: %q contains no staged templates", ErrInvalidTemplateCategory, categoryPath)
	}
	return filtered, nil
}
