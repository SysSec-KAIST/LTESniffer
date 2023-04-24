/*
 * Copyright (c) 2020 Robert Falkenberg.
 *
 * This file is part of FALCON
 * (see https://github.com/falkenber9/falcon).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 */
#include "falcon/common/Version.h"


std::string Version::gitTag() {
  return GIT_TAG;
}

std::string Version::gitDirty() {
  return GIT_DIRTY;
}

std::string Version::gitRevision() {
  return GIT_REV;
}

std::string Version::gitBranch() {
  return GIT_BRANCH;
}

std::string Version::gitVersion() {
  std::string result;
  if(GIT_REV != "N/A") {
    if(GIT_TAG != "") {
      result += GIT_TAG;
    }
    else {
      result += GIT_REV;
    }
    result += GIT_DIRTY;
    result += " on branch " + GIT_BRANCH;
  }
  else {
    result += "N/A";
  }
  return result;
}
