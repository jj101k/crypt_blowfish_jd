#!/bin/sh
old_tag=`git describe | sed 's/-g.*//'`
echo "$old_tag:" >> Changelog
git log --pretty=short $old_tag..HEAD | git shortlog >> Changelog
echo New tag?
read new_tag
git commit -m 'Release '$new_tag Changelog
git tag -a -m $new_tag $new_tag
